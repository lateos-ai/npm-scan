/**
 * D34 — Manifest confusion.
 *
 * The npm registry serves dependency and lifecycle metadata from the manifest
 * submitted at *publish* time. The `package.json` inside the published tarball
 * is a separate artifact and is never required to match it. An attacker can
 * declare a benign manifest to the registry — which is what `npm ls`, audit
 * tooling and this scanner's registry-derived detectors see — while shipping a
 * tarball whose manifest installs different dependencies or runs a different
 * lifecycle script.
 *
 * The two documents come from the same `npm publish`, so for a legitimate
 * package they are byte-for-byte equivalent apart from fields the registry
 * injects (`_id`, `dist`, `_npmUser`, `gitHead`, …). Any divergence in a
 * capability-bearing field — `dependencies`, `optionalDependencies`,
 * `peerDependencies`, `scripts`, `bin` — has no benign explanation and is
 * reported at high confidence.
 *
 * This is the one detector that operates on data the pipeline already holds in
 * scope: `registryMeta` (the registry manifest) and `pkgJson` (the tarball
 * manifest) are both passed to every detector. The comparison is a few lines;
 * the hard part is excluding the noise that would otherwise make every package
 * fire.
 */
import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import thresholds from './config/thresholds.js';

const cfg = thresholds['TIER1-MANIFEST-CONFUSION'] || {};

const PATTERN_WEIGHTS = cfg.pattern_weights || {
  dependency_divergence: 90,
  optional_dependency_divergence: 85,
  peer_dependency_divergence: 80,
  script_divergence: 100,
  bin_divergence: 90,
};

/**
 * Fields the npm registry adds to the stored manifest that are never present in
 * the tarball's own `package.json`, plus fields whose serialization legitimately
 * differs between the two representations. Diffing without stripping these makes
 * every package fire.
 */
const REGISTRY_INJECTED = new Set([
  '_id',
  '_rev',
  '_from',
  '_resolved',
  'dist',
  'directories',
  'gitHead',
  'maintainers',
  'readme',
  'readmeFilename',
  '_npmUser',
  '_nodeVersion',
  '_npmVersion',
  '_hasShrinkwrap',
  '_integrity',
  '_signatures',
  '_attestations',
  'nodejs',
  'npm',
]);

/** Lifecycle hooks whose divergence is the highest-confidence signal. */
const LIFECYCLE_KEYS = [
  'preinstall',
  'install',
  'postinstall',
  'preuninstall',
  'postuninstall',
  'prepare',
  'prepublish',
  'prepublishOnly',
];

function normalizeDepMap(obj) {
  if (!obj || typeof obj !== 'object') {
    return {};
  }
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = String(v).trim();
  }
  return out;
}

/**
 * `bin` may be a single string or a name->path map; normalize both to a sorted
 * map keyed by the command name so the representations compare structurally.
 */
function normalizeBin(bin) {
  if (!bin) {
    return {};
  }
  if (typeof bin === 'string') {
    return { '': bin };
  }
  if (typeof bin === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(bin)) {
      out[k] = String(v);
    }
    return out;
  }
  return {};
}

function normalizeScripts(scripts) {
  if (!scripts || typeof scripts !== 'object') {
    return {};
  }
  const out = {};
  for (const [k, v] of Object.entries(scripts)) {
    out[k] = String(v).trim();
  }
  return out;
}

function mapsDiffer(a, b) {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const key of keys) {
    if (a[key] !== b[key]) {
      return true;
    }
  }
  return false;
}

function diffKeys(a, b) {
  const added = [];
  const removed = [];
  const changed = [];
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const key of keys) {
    if (!(key in a)) {
      added.push(key);
    } else if (!(key in b)) {
      removed.push(key);
    } else if (a[key] !== b[key]) {
      changed.push(`${key}: "${a[key]}" -> "${b[key]}"`);
    }
  }
  return { added, removed, changed };
}

function describeDiff(diff) {
  const parts = [];
  if (diff.added.length) {
    parts.push(`added in tarball: ${diff.added.join(', ')}`);
  }
  if (diff.removed.length) {
    parts.push(`removed from tarball: ${diff.removed.join(', ')}`);
  }
  if (diff.changed.length) {
    parts.push(`changed: ${diff.changed.join('; ')}`);
  }
  return parts.join(' | ');
}

/**
 * Resolve the registry manifest for the version actually shipped in the tarball.
 * The CLI passes the `/{name}/{version}` response, which is a single-version
 * document; the full packument shape (`{ versions: { v: {...} } }`) is also
 * tolerated so this works wherever it is wired in.
 */
function registryManifestFor(registryMeta, version) {
  if (!registryMeta || typeof registryMeta !== 'object') {
    return null;
  }
  if (registryMeta.versions && typeof registryMeta.versions === 'object') {
    const v = version && registryMeta.versions[version] ? version : null;
    if (v) {
      return registryMeta.versions[v];
    }
    // Fall back to the single entry if only one version is present.
    const only = Object.values(registryMeta.versions);
    return only.length === 1 ? only[0] : null;
  }
  return registryMeta;
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

export const name = 'tier1-manifest-confusion';

export function scan(pkgJson, _files, registryMeta, _allFiles) {
  if (cfg.enabled === false) {
    return [];
  }
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  // No registry metadata (e.g. a local `--file` scan) -> nothing to compare.
  const registry = registryManifestFor(registryMeta, pkgJson?.version);
  if (!registry) {
    return [];
  }

  // Strip registry-injected fields from the tarball side too, in case a
  // hand-forged manifest carries them, so the diff is apples-to-apples.
  const tarball = { ...pkgJson };
  const reg = { ...registry };
  for (const key of REGISTRY_INJECTED) {
    delete tarball[key];
    delete reg[key];
  }

  const signals = [];

  const depPairs = [
    ['dependencies', 'dependency_divergence', normalizeDepMap],
    ['optionalDependencies', 'optional_dependency_divergence', normalizeDepMap],
    ['peerDependencies', 'peer_dependency_divergence', normalizeDepMap],
    ['scripts', 'script_divergence', normalizeScripts],
    ['bin', 'bin_divergence', normalizeBin],
  ];

  for (const [field, type, norm] of depPairs) {
    const a = norm(reg[field]);
    const b = norm(tarball[field]);
    if (mapsDiffer(a, b)) {
      signals.push({ type, field, detail: describeDiff(diffKeys(a, b)) });
    }
  }

  // A lifecycle hook present only in the tarball is the canonical manifest-
  // confusion payload; escalate it explicitly.
  const tarballScripts = normalizeScripts(tarball.scripts);
  const registryScripts = normalizeScripts(reg.scripts);
  const hookOnlyInTarball = LIFECYCLE_KEYS.filter(
    (hook) => tarballScripts[hook] && !registryScripts[hook]
  );

  if (signals.length === 0) {
    return [];
  }

  let score = 0;
  const evidence = [];
  for (const s of signals) {
    score += PATTERN_WEIGHTS[s.type] || 0;
    evidence.push(`${s.field}: ${s.detail}`);
  }
  if (hookOnlyInTarball.length) {
    evidence.push(`lifecycle_hook_only_in_tarball: ${hookOnlyInTarball.join(', ')}`);
  }

  const overallScore = Math.min(100, score);
  const severity =
    hookOnlyInTarball.length || overallScore >= 100
      ? 'critical'
      : overallScore >= 90
        ? 'high'
        : 'medium';

  const hasScript = signals.some((s) => s.type === 'script_divergence');
  const hasDep = signals.some((s) => s.type.endsWith('dependency_divergence'));

  let message;
  if (hasScript) {
    message = 'Tarball lifecycle scripts differ from the registry manifest';
  } else if (hasDep) {
    message = 'Tarball dependencies differ from the registry manifest';
  } else {
    message = 'Tarball manifest diverges from the registry manifest';
  }

  return [
    {
      detector: 'tier1-manifest-confusion',
      id: 'TIER1-MANIFEST-CONFUSION',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message,
      evidence: [
        `aggregated_risk: ${score}`,
        `fields: ${signals.map((s) => s.field).join(', ')}`,
        ...evidence,
      ],
      locations: [{ file: 'package.json', line: 1 }],
      recommendation: hookOnlyInTarball.length
        ? 'BLOCK - Tarball ships a lifecycle hook the registry manifest does not declare'
        : 'BLOCK - Published tarball does not match the registry manifest',
      detail: signals.map((s) => ({
        type: s.type,
        field: s.field,
        description: s.detail,
        risk: PATTERN_WEIGHTS[s.type] || 0,
      })),
      reference: 'Manifest confusion (registry metadata != shipped code)',
    },
  ];
}
