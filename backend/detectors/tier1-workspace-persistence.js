/**
 * D30 — Agent/IDE workspace persistence.
 *
 * Targets the surface that needs no lifecycle hook, survives
 * `--ignore-scripts`, and executes with full developer privileges the next
 * time an agent or editor starts: `.claude/`, `.cursor/rules/`, `.vscode/`
 * and `.github/workflows/`.
 *
 * The gap this closes is path *reconstruction*. Every previous check was a
 * literal substring test against raw source, so ATK-004's single
 * `/mkdir.*(\.vscode|\.claude|\.cursor)/` regex missed the actual attack — a
 * write, not a mkdir — and missed every dynamically assembled path
 * (findings G3.4, G3.5, G3.6). Paths are folded through
 * lib/path-resolver.js first, so all of these resolve to the same target:
 *
 *   fs.writeFileSync(process.env.HOME + '/.claude/mcp.json', p)
 *   ['.','claude'].join('') + '/' + ['mcp','json'].join('.')
 *   path.join(process.cwd(), '.cursor', 'rules')
 *   String.fromCharCode(46,99,108,97,117,100,101)
 *
 * Severity follows the surface band, not the syntax: an injected *instruction*
 * is high (an agent must comply), an injected *server command* is critical
 * (it executes unconditionally).
 */
import path from 'path';
import * as walk from 'acorn-walk';
import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import { parseSource, lineOf } from './lib/ast-parse.js';
import { CAPABILITY, buildRuntimeIndex, classifyNode } from './lib/runtime-primitives.js';
import { resolvePathExpr, isDynamicExpr, collectBindings } from './lib/path-resolver.js';
import { matchSurface, hasSurfaceMarker, BAND } from './lib/agent-surfaces.js';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D30-WORKSPACE-PERSISTENCE'];
const PATTERN_WEIGHTS = cfg.pattern_weights;

const PARSABLE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs']);

/** Shell interpreters that turn a config value into arbitrary execution. */
const SHELL_COMMANDS = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'env',
]);

const NETWORK_IN_ARGS_RE = /\b(?:curl|wget|iwr|Invoke-WebRequest|fetch)\b|https?:\/\//i;

/**
 * Prefilter support for *assembled* paths. A file building `.claude/mcp.json`
 * out of `['.','claude'].join('')` never contains the literal `.claude`, so
 * the precise dotted markers alone would skip it before parsing — the exact
 * prefilter/AST mismatch that silently disables a signal. Requiring a write
 * sink *and* a bare surface word keeps the gate tight without missing
 * assembly.
 */
const WRITE_SINK_RE =
  /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|mkdir|mkdirSync|copyFile|copyFileSync|rename|renameSync|writeTextFile|writeTextFileSync)\b|Bun\s*\.\s*write/;
const SURFACE_WORD_RE =
  /\b(?:claude|cursor|vscode|windsurf|devcontainer|mcp|workflows|cursorrules|windsurfrules)\b/i;
const CHARCODE_RE = /String\s*\.\s*fromCharCode/;

function extOf(file) {
  return path.extname((file?.path || file?.name || '').toLowerCase());
}

function isParsable(file) {
  return PARSABLE_EXTENSIONS.has(extOf(file));
}

/**
 * Which argument of a write call carries the destination path. For every sink
 * modelled here it is the first, including `Bun.write` and `Deno.writeTextFile`.
 */
function pathArgOf(node) {
  return node.arguments?.[0] ?? null;
}

/* ------------------------------------------------------------------ *
 * 1. Code that WRITES to a workspace surface                          *
 * ------------------------------------------------------------------ */

function analyzeWrites(file) {
  const content = file.content || '';
  const filePath = file.path || file.name || 'unknown.js';
  const signals = [];

  if (!content || content.length > cfg.max_file_bytes) {
    return signals;
  }
  // Gate before parsing. Either a precise dotted surface marker, or a write
  // sink paired with a bare surface word / charcode assembly — the latter is
  // what keeps runtime-assembled paths in scope.
  const precise = hasSurfaceMarker(content);
  const assembled =
    WRITE_SINK_RE.test(content) && (SURFACE_WORD_RE.test(content) || CHARCODE_RE.test(content));
  if (!precise && !assembled) {
    return signals;
  }

  const parsed = parseSource(content);
  if (!parsed.ast) {
    return signals;
  }

  const index = buildRuntimeIndex(parsed.ast);
  const bindings = collectBindings(parsed.ast);

  walk.full(parsed.ast, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }
    const hit = classifyNode(node, index);
    if (!hit || hit.capability !== CAPABILITY.FS_WRITE) {
      return;
    }

    const arg = pathArgOf(node);
    if (!arg) {
      return;
    }
    const folded = resolvePathExpr(arg, { bindings });
    if (!folded) {
      return;
    }
    const surface = matchSurface(folded.value);
    if (!surface) {
      return;
    }

    const dynamic = isDynamicExpr(arg);
    signals.push({
      type: dynamic ? 'dynamic_surface_write' : 'static_surface_write',
      detail: `${hit.path}() writes to ${surface.label} at "${folded.value}"${
        dynamic ? ' (path assembled at runtime)' : ''
      }`,
      file: filePath,
      line: lineOf(content, node.start ?? 0),
      band: surface.band,
      surface: surface.label,
      resolvedPath: folded.value,
      pathConfidence: folded.confidence,
      runtime: hit.runtime,
      sink: hit.path,
    });
  });

  return signals;
}

/* ------------------------------------------------------------------ *
 * 2. Executable agent config SHIPPED inside the tarball               *
 * ------------------------------------------------------------------ */

function collectCommandStrings(value, out, depth = 0) {
  if (depth > 6 || value === null || value === undefined) {
    return;
  }
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v) => collectCommandStrings(v, out, depth + 1));
    return;
  }
  if (typeof value === 'object') {
    Object.values(value).forEach((v) => collectCommandStrings(v, out, depth + 1));
  }
}

/**
 * A package that legitimately *is* an MCP server ships an MCP config that
 * launches itself with node/npx. That is normal and must not fire. What is not
 * normal is a shell interpreter, an inline `-c` payload, or a network fetch.
 */
function inspectMcpConfig(parsed) {
  const servers = parsed?.mcpServers || parsed?.servers;
  if (!servers || typeof servers !== 'object') {
    return null;
  }
  for (const [serverName, server] of Object.entries(servers)) {
    if (!server || typeof server !== 'object') {
      continue;
    }
    const command = String(server.command || '');
    const base = command.split(/[\\/]/).pop().toLowerCase();
    const args = Array.isArray(server.args) ? server.args : [];
    const argText = args.map(String).join(' ');

    if (SHELL_COMMANDS.has(base)) {
      return `MCP server "${serverName}" launches a shell interpreter: ${command} ${argText}`.trim();
    }
    if (/(^|\s)-c(\s|$)/.test(argText) || /(^|\s)-Command(\s|$)/i.test(argText)) {
      return `MCP server "${serverName}" passes an inline command payload: ${argText.slice(0, 120)}`;
    }
    if (NETWORK_IN_ARGS_RE.test(argText)) {
      return `MCP server "${serverName}" fetches from the network at startup: ${argText.slice(0, 120)}`;
    }
    if (path.isAbsolute(command) && !/node|npx|bun|deno/i.test(base)) {
      return `MCP server "${serverName}" runs an absolute path outside the package: ${command}`;
    }
  }
  return null;
}

function inspectVsCodeTasks(parsed) {
  for (const task of parsed?.tasks || []) {
    if (!task || typeof task !== 'object') {
      continue;
    }
    const runOn = task.runOptions?.runOn;
    if (runOn && String(runOn).toLowerCase() === 'folderopen') {
      const cmd = [task.command, ...(Array.isArray(task.args) ? task.args : [])]
        .filter(Boolean)
        .join(' ');
      return `VS Code task "${task.label || 'unnamed'}" runs on folderOpen: ${String(cmd).slice(0, 120)}`;
    }
  }
  return null;
}

function inspectHooks(parsed) {
  const hooks = parsed?.hooks;
  if (!hooks || typeof hooks !== 'object') {
    return null;
  }
  const commands = [];
  collectCommandStrings(hooks, commands);
  const suspicious = commands.find(
    (c) => NETWORK_IN_ARGS_RE.test(c) || /\b(?:sh|bash|powershell|pwsh)\b\s+-c/i.test(c)
  );
  if (suspicious) {
    return `hook command runs a shell or network fetch: ${suspicious.slice(0, 120)}`;
  }
  return commands.length ? `hook commands declared: ${commands[0].slice(0, 120)}` : null;
}

/* ------------------------------------------------------------------ *
 * 3. Shipped GitHub Actions workflow content                        *
 * ------------------------------------------------------------------ */

const PRIVILEGED_TRIGGER_RE = /pull_request_target|workflow_run/;
const SECRET_REF_RE = /\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}/;
const RAW_IP_TARGET_RE = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/;
const URL_HOST_RE = /https?:\/\/([^/\s"'>{}]+)/gi;
// GhostAction: `fetch-depth: 0` + `git log -p --all` reconstructs the full
// patch history, then a grep sweep pulls committed credentials out of it.
const HISTORY_SWEEP_RE = /fetch-depth:\s*0|git\s+log\s+[^|\n]*--all|git\s+log\s+-p\b/;
const CRED_GREP_RE =
  /grep\b[^\n]*(AKIA|sk-|ghp_|github_pat_|BEGIN [A-Z ]*PRIVATE KEY|secret[_ ]?access[_ ]?key)/i;

// Hosts a legitimate workflow is expected to talk to with a bound secret
// (package publish, API calls). Exfiltration to any other destination is the
// signal; publishing to your own registry is not.
const ALLOWED_WORKFLOW_HOSTS =
  /^(?:[\w-]+\.)*(?:npmjs\.org|npmjs\.com|yarnpkg\.com|pypi\.org|rubygems\.org|crates\.io|github\.com|githubusercontent\.com|gitlab\.com|bitbucket\.org|docker\.com|docker\.io|ghcr\.io|nuget\.org|nodejs\.org|amazonaws\.com|azure\.com|googleapis\.com|cloud\.google\.com|vaultproject\.io)$/i;

function hasOffAllowlistTarget(content) {
  URL_HOST_RE.lastIndex = 0;
  let match;
  while ((match = URL_HOST_RE.exec(content)) !== null) {
    const host = match[1].toLowerCase();
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
      return true; // raw IP is never an allowlisted publishing endpoint
    }
    if (!ALLOWED_WORKFLOW_HOSTS.test(host)) {
      return true;
    }
  }
  return false;
}

/**
 * @returns {{type: string, detail: string}|null} the strongest workflow signal
 */
function inspectWorkflowContent(content) {
  const secretBound = SECRET_REF_RE.test(content);
  const historySweep = HISTORY_SWEEP_RE.test(content) && CRED_GREP_RE.test(content);
  const secretToForeignHost = secretBound && hasOffAllowlistTarget(content);
  const secretToIp = secretBound && RAW_IP_TARGET_RE.test(content);

  if (historySweep || secretToForeignHost || secretToIp) {
    const why = historySweep
      ? 'sweeps git history for committed credentials'
      : 'sends bound secrets to a non-allowlisted destination';
    return {
      type: 'shipped_workflow_secret_exfil',
      detail: `shipped workflow ${why}: ${content.match(/.{0,80}/)?.[0] || ''}`.slice(0, 200),
    };
  }
  if (PRIVILEGED_TRIGGER_RE.test(content)) {
    return {
      type: 'shipped_workflow_privileged_trigger',
      detail: 'shipped workflow uses a privileged trigger',
    };
  }
  return null;
}

function analyzeShippedConfig(file, pkgJson) {
  const filePath = file.path || file.name || '';
  const surface = matchSurface(filePath);
  if (!surface || surface.band !== BAND.EXEC) {
    return [];
  }

  const content = file.content || '';
  if (!content || content.length > cfg.max_file_bytes) {
    return [];
  }

  // GitHub Actions workflows are YAML; the content decides the signal.
  if (/\.ya?ml$/i.test(filePath)) {
    const wf = inspectWorkflowContent(content);
    return [
      {
        type: wf ? wf.type : 'shipped_exec_config',
        detail: wf
          ? `${wf.detail} (${filePath})`
          : `package ships a GitHub Actions workflow: ${filePath}`,
        file: filePath,
        line: 1,
        band: surface.band,
        surface: surface.label,
      },
    ];
  }

  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  // A package that declares itself an MCP server legitimately ships one.
  const declaresMcp =
    (pkgJson?.keywords || []).some((k) => String(k).toLowerCase().includes('mcp')) ||
    /\bmcp\b/i.test(String(pkgJson?.name || ''));

  const detail =
    inspectMcpConfig(parsed) || inspectVsCodeTasks(parsed) || inspectHooks(parsed) || null;
  if (!detail) {
    return [];
  }

  // Suppress only the benign self-launch case, never a shell or network payload.
  const dangerous = /shell interpreter|inline command|network|absolute path|folderOpen/i.test(
    detail
  );
  if (declaresMcp && !dangerous) {
    return [];
  }

  return [
    {
      type: 'shipped_exec_config',
      detail,
      file: filePath,
      line: 1,
      band: surface.band,
      surface: surface.label,
    },
  ];
}

/* ------------------------------------------------------------------ */

function confidenceLabel(score) {
  if (score >= 80) {
    return 'HIGH';
  }
  if (score >= 50) {
    return 'MEDIUM';
  }
  return 'LOW';
}

const BAND_RANK = { [BAND.EXEC]: 3, [BAND.AGENT_READ]: 2, [BAND.EDITOR_CONFIG]: 1 };

export const name = 'tier1-workspace-persistence';

export function scan(pkgJson, jsFiles, _registryMeta, allFiles) {
  if (cfg.enabled === false) {
    return [];
  }
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  const files = allFiles || jsFiles || [];
  if (files.length === 0) {
    return [];
  }

  const signals = [];
  for (const file of files) {
    if (isParsable(file)) {
      signals.push(...analyzeWrites(file));
    }
    signals.push(...analyzeShippedConfig(file, pkgJson));
  }

  if (signals.length === 0) {
    return [];
  }

  // Score once per (signal type + band) so a package writing to five files
  // under .claude/ is not scored five times.
  let score = 0;
  const counted = new Set();
  const scored = [];
  for (const signal of signals) {
    const key = `${signal.type}:${signal.band || ''}`;
    if (counted.has(key)) {
      continue;
    }
    counted.add(key);
    const base = PATTERN_WEIGHTS[signal.type] || 0;
    const bandBonus = cfg.band_weights[signal.band] || 0;
    score += base + bandBonus;
    scored.push(signal);
  }

  if (score < cfg.warn_threshold) {
    return [];
  }

  const overallScore = Math.min(100, score);
  const topBand = scored.reduce(
    (acc, s) => (BAND_RANK[s.band] > BAND_RANK[acc] ? s.band : acc),
    BAND.EDITOR_CONFIG
  );
  const hasDynamic = scored.some((s) => s.type === 'dynamic_surface_write');
  const hasShipped = scored.some(
    (s) =>
      s.type === 'shipped_exec_config' ||
      s.type === 'shipped_workflow_privileged_trigger' ||
      s.type === 'shipped_workflow_secret_exfil'
  );

  let severity;
  let recommendation;
  if (topBand === BAND.EXEC) {
    severity = 'critical';
    recommendation = hasShipped
      ? 'BLOCK - Package ships executable agent/editor configuration'
      : 'BLOCK - Package writes to executable agent/editor configuration';
  } else if (topBand === BAND.AGENT_READ) {
    severity = 'high';
    recommendation = 'INVESTIGATE - Package writes to agent instruction files';
  } else {
    severity = score >= cfg.flag_threshold ? 'high' : 'medium';
    recommendation = 'REVIEW - Package writes to editor workspace configuration';
  }

  return [
    {
      detector: 'tier1-workspace-persistence',
      id: 'D30-WORKSPACE-PERSISTENCE',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Agent/IDE workspace persistence detected (${topBand}; aggregated risk: ${score})`,
      evidence: [
        `aggregated_risk: ${score}`,
        `highest_band: ${topBand}`,
        `dynamic_path_construction: ${hasDynamic}`,
        `signals: ${scored.map((s) => s.type).join(', ')}`,
        ...scored.map((s) => `${s.type}: ${s.detail} @ ${s.file}:${s.line}`),
      ],
      locations: scored.map((s) => ({ file: s.file, line: s.line })),
      recommendation,
      detail: scored.map((s) => ({
        type: s.type,
        description: s.detail,
        band: s.band,
        surface: s.surface || null,
        resolved_path: s.resolvedPath || null,
        path_confidence: s.pathConfidence || null,
        risk: (PATTERN_WEIGHTS[s.type] || 0) + (cfg.band_weights[s.band] || 0),
        location: { file: s.file, line: s.line },
      })),
      reference: 'Agent/IDE workspace persistence (ChainDrop-class)',
    },
  ];
}
