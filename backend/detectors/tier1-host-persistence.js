/**
 * D32 — Host-level persistence and dead-man's switch.
 *
 * Closes the keyv/cacheable (2026-08-04) gap. The existing persistence checks
 * (`msh-supplement/d2-persistence.js`, `axios-poisoning/d3`) cover *system*
 * units — `/etc/systemd/system/`, `/Library/LaunchDaemons/`. The 2026 worm
 * instead persists at the **user** level and arms a **dead-man's switch**:
 *
 *   ~/Library/LaunchAgents/com.user.*.plist   (RunAtLoad + KeepAlive)
 *   ~/.config/systemd/user/*.service          (systemctl --user)
 *   loginctl enable-linger                     (survives logout)
 *   ~/.config/gh-token-monitor/{token,handler}
 *   poll the credential API every N seconds; on HTTP 4xx (revocation) ->
 *   eval a remote-supplied handler, then delete its own state
 *
 * The dead-man's switch is the load-bearing signal: no legitimate tool installs
 * a background service that watches for its own credential being revoked and
 * then evaluates a string it fetched from the network. It is gated as an anchor
 * so the persistence-path regexes alone cannot produce a false positive on a
 * package that merely mentions `systemd`.
 *
 * This detector is regex-driven (like d2-persistence) with one AST pass to
 * distinguish `eval(variable)` from `eval("literal")`.
 */
import * as walk from 'acorn-walk';
import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import { parseSource, lineOf } from './lib/ast-parse.js';
import { buildRuntimeIndex, classifyNode, CAPABILITY } from './lib/runtime-primitives.js';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D32-HOST-PERSISTENCE'] || {};
const PATTERN_WEIGHTS = cfg.pattern_weights || {
  deadman_switch: 95,
  launch_agent_user: 85,
  loginctl_linger: 85,
  systemd_user_unit: 80,
  launchctl_plist_write: 75,
  self_destruct_threshold: 65,
  token_monitor_poll: 60,
};

const ANCHORS = new Set(
  cfg.anchor_signals || [
    'deadman_switch',
    'launch_agent_user',
    'loginctl_linger',
    'systemd_user_unit',
    'launchctl_plist_write',
  ]
);

const LAUNCH_AGENT_PATH_RE = /(?:^|[\s'"`(])~?\/?Library\/LaunchAgents\//;
const PLIST_AUTOSTART_RE =
  /\b(?:RunAtLoad|KeepAlive|StartInterval|StartAtCalendar|LimitLoadToSessionType)\b/;
const SYSTEMD_USER_RE = /\.config\/systemd\/user\/|systemctl\s+--(?:user|global)\b/;
const LINGER_RE = /loginctl\s+enable-linger|enable-linger\b/;
const LAUNCHCTL_RE = /launchctl\s+(?:load|bootout|submit|enable|bootstrap)\b/;
const TOKEN_POLL_RE =
  /registry\.npmjs\.org\/-\/(?:whoami|v1\/tokens)|api\.github\.com\/(?:user|graphql)|\/-\/v1\/search\?text=maintainer|gh\s+auth\s+status|POST \/user\/repos|\/user\/repos\b/;
const DEADMAN_STATUS_RE =
  /(?:status|code|statusCode|HTTP_STATUS|response\.status)\s*(?:=~|===?|>=|<=|==)\s*[^\n]*40\d|40[0-9]\$?|token.{0,24}(?:revoked|invalid|expired)|(?:revoked|invalid).{0,24}token/i;
const SELF_DELETE_RE = /\b(?:rm\s+-f|rmSync|unlinkSync|unlink|fs\.rm\b|removeSync)\b/;
const POLL_INTERVAL_RE = /\b(?:setInterval|sleep\s+\d|every\s+\d+\s*sec|60000|60\s*\*\s*1000)\b/;

const PARSABLE = new Set(['.js', '.mjs', '.cjs']);

function extOf(file) {
  const p = (file.path || file.name || '').toLowerCase();
  const dot = p.lastIndexOf('.');
  return dot === -1 ? '' : p.slice(dot);
}

/** A CallExpression callee's dotted name, e.g. `eval`, `child_process.execSync`. */
function calleeName(node) {
  if (!node.callee) {
    return null;
  }
  if (node.callee.type === 'Identifier') {
    return node.callee.name;
  }
  if (node.callee.type === 'MemberExpression' && !node.callee.computed) {
    const obj = node.callee.object?.name;
    const prop = node.callee.property?.name;
    if (obj && prop) {
      return `${obj}.${prop}`;
    }
    return prop || null;
  }
  return null;
}

/**
 * True when the file evaluates a *non-literal* string through eval/Function/
 * exec — i.e. the handler comes from a variable (the network), not a constant.
 */
function hasDynamicEvalOrExec(ast, index) {
  let found = false;
  walk.full(ast, (node) => {
    if (found) {
      return;
    }
    if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      const name = calleeName(node);
      const isEvalLike = name === 'eval' || name === 'Function';
      const hit = classifyNode(node, index);
      const isExec = hit && hit.capability === CAPABILITY.EXEC;
      if (!isEvalLike && !isExec) {
        return;
      }
      const args = node.arguments || [];
      const payload = node.type === 'NewExpression' ? args[args.length - 1] : args[0];
      if (payload && payload.type !== 'Literal' && payload.type !== 'TemplateLiteral') {
        found = true;
      } else if (
        payload &&
        payload.type === 'TemplateLiteral' &&
        payload.expressions &&
        payload.expressions.length > 0
      ) {
        found = true;
      }
    }
  });
  return found;
}

function firstLine(content, regex) {
  regex.lastIndex = 0;
  const m = regex.exec(content);
  return m ? lineOf(content, m.index) : 1;
}

function analyzeFile(file) {
  const content = file.content || '';
  const filePath = file.path || file.name || '';
  if (!content || content.length > (cfg.max_file_bytes || 512000)) {
    return [];
  }
  const signals = [];
  const push = (type, line, detail) => signals.push({ type, file: filePath, line, detail });

  const plist = LAUNCH_AGENT_PATH_RE.test(content);
  if (plist && PLIST_AUTOSTART_RE.test(content)) {
    push(
      'launch_agent_user',
      firstLine(content, LAUNCH_AGENT_PATH_RE),
      'installs a user LaunchAgent with autostart keys'
    );
  } else if (plist) {
    push(
      'launch_agent_user',
      firstLine(content, LAUNCH_AGENT_PATH_RE),
      'writes to ~/Library/LaunchAgents'
    );
  }

  if (SYSTEMD_USER_RE.test(content)) {
    push(
      'systemd_user_unit',
      firstLine(content, SYSTEMD_USER_RE),
      'installs a user-level systemd unit (systemctl --user / ~/.config/systemd/user)'
    );
  }

  if (LINGER_RE.test(content)) {
    push(
      'loginctl_linger',
      firstLine(content, LINGER_RE),
      'enables loginctl linger to survive logout'
    );
  }

  if (LAUNCHCTL_RE.test(content) && (plist || /\.plist/.test(content))) {
    push(
      'launchctl_plist_write',
      firstLine(content, LAUNCHCTL_RE),
      'loads a LaunchAgent plist via launchctl'
    );
  }

  const polls = TOKEN_POLL_RE.test(content);
  if (polls) {
    push(
      'token_monitor_poll',
      firstLine(content, TOKEN_POLL_RE),
      'polls a credential-validity endpoint'
    );
  }

  if (SELF_DELETE_RE.test(content) && (polls || DEADMAN_STATUS_RE.test(content))) {
    push('self_destruct_threshold', 1, 'deletes its own state on failure/expiry');
  }

  // Dead-man's switch: dynamic eval/exec correlated with a revocation/status
  // check or a credential poll loop. AST-gated so `eval("literal")` never fires.
  if (
    (DEADMAN_STATUS_RE.test(content) || (polls && POLL_INTERVAL_RE.test(content))) &&
    PARSABLE.has(extOf(file))
  ) {
    const parsed = parseSource(content);
    if (parsed.ast) {
      const index = buildRuntimeIndex(parsed.ast);
      if (hasDynamicEvalOrExec(parsed.ast, index)) {
        push(
          'deadman_switch',
          firstLine(content, DEADMAN_STATUS_RE),
          'evaluates a variable-supplied handler when its credential is revoked'
        );
      }
    }
  }

  return signals;
}

function confidenceLabel(score) {
  if (score >= 80) {
    return 'HIGH';
  }
  if (score >= 50) {
    return 'MEDIUM';
  }
  return 'LOW';
}

export const name = 'tier1-host-persistence';

export function scan(pkgJson, _jsFiles, _registryMeta, allFiles) {
  if (cfg.enabled === false) {
    return [];
  }
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  const files = allFiles || [];
  const signals = [];
  for (const file of files) {
    signals.push(...analyzeFile(file));
  }

  if (signals.length === 0) {
    return [];
  }

  // A finding requires at least one anchor; supporting signals only modulate.
  const anchored = signals.some((s) => ANCHORS.has(s.type));
  if (!anchored) {
    return [];
  }

  let score = 0;
  const counted = new Set();
  for (const s of signals) {
    if (counted.has(s.type)) {
      continue;
    }
    counted.add(s.type);
    score += PATTERN_WEIGHTS[s.type] || 0;
  }

  if (score < (cfg.warn_threshold || 60)) {
    return [];
  }

  const overallScore = Math.min(100, score);
  const hasDeadman = counted.has('deadman_switch');
  const severity = hasDeadman || overallScore >= (cfg.flag_threshold || 80) ? 'critical' : 'high';

  return [
    {
      detector: 'tier1-host-persistence',
      id: 'D32-HOST-PERSISTENCE',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: hasDeadman
        ? 'Host-level persistence with a dead-man switch detected'
        : `Host-level persistence mechanism detected (aggregated risk: ${score})`,
      evidence: [
        `aggregated_risk: ${score}`,
        `deadman_switch: ${hasDeadman}`,
        ...signals.map((s) => `${s.type}: ${s.detail} @ ${s.file}:${s.line}`),
      ],
      locations: signals.map((s) => ({ file: s.file, line: s.line })),
      recommendation: hasDeadman
        ? 'BLOCK - Installs user-level persistence and evaluates a remote handler on credential revocation'
        : 'BLOCK - Package installs a host-level persistence mechanism',
      detail: signals.map((s) => ({
        type: s.type,
        description: s.detail,
        anchor: ANCHORS.has(s.type),
        risk: PATTERN_WEIGHTS[s.type] || 0,
        location: { file: s.file, line: s.line },
      })),
      reference: 'Host persistence + dead-man switch (keyv/cacheable, 2026-08)',
    },
  ];
}
