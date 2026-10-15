/**
 * D33 — Install-time configuration abuse.
 *
 * Every lifecycle detector (ATK-001, D3, D3b, D6b) keys off `package.json`
 * scripts. The package-manager ecosystem has several *other* files that execute
 * code at install time or on every install of a dependency, and none of them
 * were examined (gap-analysis-2026-08.md §5):
 *
 *   .pnpmfile.cjs   hooks.readPackage() runs arbitrary Node on every install and
 *                   can rewrite any dependency's manifest in memory.
 *   .yarnrc.yml     `plugins:` loads JS from a path or URL at command time.
 *   bunfig.toml     `[preload]` loads JS on every `bun` run; `trustedDependencies`
 *                   re-enables lifecycle scripts Bun blocks by default.
 *   overrides /     `package.json` `overrides`/`resolutions` silently substitute a
 *   resolutions     transitive dependency's *source* across the whole tree.
 *
 * The asymmetry this corrects: D24 detects Bun *runtime* abuse but not the
 * `bunfig.toml` that authorizes it; the lifecycle detectors see a clean
 * `package.json` while the payload lives in one of these files.
 *
 * Calibration (§5 note): presence of a `.pnpmfile.cjs` is NOT suspicious on its
 * own — legitimate monorepo use is common. Score on *content*: a hook that
 * reaches outside the package (exec / network) or rewrites a dependency.
 */
import path from 'path';
import yaml from 'js-yaml';
import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D33-INSTALL-CONFIG-ABUSE'] || {};
const PATTERN_WEIGHTS = cfg.pattern_weights || {
  pnpmfile_mutates_and_dispatches: 85,
  yarnrc_external_plugin: 80,
  bunfig_preload: 75,
  pnpmfile_dispatch: 70,
  override_resolved_off_registry: 80,
  bunfig_trusted_dependencies: 55,
};

const DISPATCH_RE =
  /\b(?:require\s*\(\s*['"](?:node:)?(?:child_process|http|https|net|dns|tls)['"]\s*\)|child_process|\bexec(?:Sync|File)?\s*\(|\bspawn(?:Sync)?\s*\(|\bfetch\s*\(|axios|got\s*\(|\bcurl\b|\bwget\b)/i;
const REWRITE_RE =
  /\.(?:scripts|dependencies|devDependencies|optionalDependencies|_dependencies|packageManager)\b\s*(?:=|\[)|\.scripts\s*=|manifest\.(?:scripts|dependencies)/i;
const READPACKAGE_RE = /readPackage|hooks\s*\.\s*readPackage|\.hooks\s*=\s*\{/i;

// Protocol specs that bypass the registry entirely. Cleartext http, ssh, and
// local file/link targets are attacker-favorable and rare in a legitimate
// override; `github:`/`git+https:`/`npm:` aliasing are common enough to skip.
const OFF_REGISTRY_RE =
  /(?:^|\s)(?:git\+ssh:\/\/|ssh:\/\/|http:\/\/|file:\/\/|link:|\\\\|[A-Za-z]:\\)/;

function baseName(file) {
  return (file.path || file.name || '').split(/[/\\]/).pop().toLowerCase();
}

function analyzePnpmfile(file) {
  const content = file.content || '';
  if (!content) {
    return [];
  }
  const dispatch = DISPATCH_RE.test(content);
  const rewrite = REWRITE_RE.test(content);
  const hasHook = READPACKAGE_RE.test(content);

  if (dispatch && (rewrite || hasHook)) {
    return [
      {
        type: 'pnpmfile_mutates_and_dispatches',
        detail: '.pnpmfile.cjs hook rewrites a dependency manifest and reaches outside the package',
      },
    ];
  }
  if (dispatch) {
    return [
      {
        type: 'pnpmfile_dispatch',
        detail: '.pnpmfile.cjs executes a child process or network call on every install',
      },
    ];
  }
  return [];
}

function analyzeYarnRc(file) {
  const content = file.content || '';
  let doc;
  try {
    doc = yaml.load(content);
  } catch {
    // `.yarnrc` (v1) is not YAML; fall back to a line scan for `plugins`.
    if (/^\s*plugins\s+\S+\s+(?:https?:|git|file:|\/|\.\.)/m.test(content)) {
      return [
        {
          type: 'yarnrc_external_plugin',
          detail: '.yarnrc loads a plugin from an off-package location',
        },
      ];
    }
    return [];
  }
  if (!doc || typeof doc !== 'object') {
    return [];
  }
  const plugins = doc.plugins;
  if (!Array.isArray(plugins)) {
    return [];
  }
  for (const p of plugins) {
    const spec = String((p && (p.path || p.spec)) || '');
    const looksExternal =
      /^(https?:|git\+:|file:|\/|~\/|\.\.)/.test(spec) ||
      /(^|[\\/])\.\.([\\/]|$)/.test(spec) ||
      OFF_REGISTRY_RE.test(spec);
    if (looksExternal) {
      return [
        {
          type: 'yarnrc_external_plugin',
          detail: `.yarnrc.yml loads a plugin from an off-package location: ${spec.slice(0, 120)}`,
        },
      ];
    }
  }
  return [];
}

function analyzeBunfig(file) {
  const content = file.content || '';
  const signals = [];
  if (/\bpreloads?\b\s*=|preload\s*=|\[preload\]/i.test(content)) {
    signals.push({
      type: 'bunfig_preload',
      detail: 'bunfig.toml preloads a module on every bun run',
    });
  }
  if (/trustedDependencies\s*=|\[install\][\s\S]*trusted/i.test(content)) {
    signals.push({
      type: 'bunfig_trusted_dependencies',
      detail: 'bunfig.toml re-enables lifecycle scripts for named packages',
    });
  }
  return signals;
}

function collectOverrideValues(obj, out) {
  if (!obj || typeof obj !== 'object') {
    return;
  }
  for (const v of Object.values(obj)) {
    if (typeof v === 'string') {
      out.push(v);
    } else if (v && typeof v === 'object') {
      collectOverrideValues(v, out);
    }
  }
}

function analyzeOverrides(pkgJson) {
  const values = [];
  collectOverrideValues(pkgJson?.overrides, values);
  collectOverrideValues(pkgJson?.resolutions, values);
  const bad = values.filter((v) => OFF_REGISTRY_RE.test(v));
  if (bad.length === 0) {
    return [];
  }
  return [
    {
      type: 'override_resolved_off_registry',
      detail: `overrides/resolutions fetch a dependency from outside the registry: ${bad[0].slice(0, 120)}`,
    },
  ];
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

export const name = 'tier1-install-config-abuse';

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
    const bn = baseName(file);
    const ext = path.extname(bn);
    const filePath = file.path || file.name || '';
    let found = [];
    if (bn === '.pnpmfile.cjs' || bn === '.pnpmfile.js') {
      found = analyzePnpmfile(file);
    } else if (bn === '.yarnrc.yml' || bn === '.yarnrc') {
      found = analyzeYarnRc(file);
    } else if (bn === 'bunfig.toml' && ext === '.toml') {
      found = analyzeBunfig(file);
    }
    for (const s of found) {
      s.file = filePath;
    }
    signals.push(...found);
  }

  const overrideSignals = analyzeOverrides(pkgJson);
  for (const s of overrideSignals) {
    s.file = 'package.json';
  }
  signals.push(...overrideSignals);

  if (signals.length === 0) {
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
  const severity =
    overallScore >= (cfg.flag_threshold || 80)
      ? 'critical'
      : overallScore >= 70
        ? 'high'
        : 'medium';

  return [
    {
      detector: 'tier1-install-config-abuse',
      id: 'D33-INSTALL-CONFIG-ABUSE',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Install-time configuration abuse detected (aggregated risk: ${score})`,
      evidence: [`aggregated_risk: ${score}`, ...signals.map((s) => s.detail)],
      locations: signals.map((s) => ({ file: s.file || 'package.json', line: 1 })),
      recommendation:
        'BLOCK - Package authorizes install-time code execution outside package.json scripts',
      detail: signals.map((s) => ({
        type: s.type,
        description: s.detail,
        risk: PATTERN_WEIGHTS[s.type] || 0,
      })),
      reference: 'Install hooks outside package.json (.pnpmfile / .yarnrc / bunfig / overrides)',
    },
  ];
}
