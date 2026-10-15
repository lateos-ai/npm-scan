import { readFileSync } from 'fs';
import { resolve as _resolve, dirname as _dirname } from 'path';
import yaml from 'js-yaml';

// gap-analysis-2026-08 §3: lockfile `resolved` URLs are parsed for all three
// formats and then discarded. A dependency resolving to a cleartext host, a
// git+ssh remote, or an unexpected registry passes without comment. These are
// the default-trusted registry hosts; private registries are added via policy
// (`allow.registries`) so the check is usable in enterprise environments.
const DEFAULT_ALLOWED_REGISTRIES = [
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'registry.npmjs.com',
];

// Public source forges. A `git+https`/`https` resolved to one of these is a
// direct git dependency — visible and common — so it is not flagged as an
// unexpected host. Flagging every GitHub dependency would be unusably noisy.
const KNOWN_GIT_HOSTS = new Set([
  'github.com',
  'codeload.github.com',
  'raw.githubusercontent.com',
  'gitlab.com',
  'bitbucket.org',
]);

function normalizeRegistryEntry(entry) {
  return String(entry)
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');
}

function hostMatchesAllowlist(host, allowed) {
  const h = host.toLowerCase();
  return allowed.some((entry) => {
    const e = normalizeRegistryEntry(entry);
    return e && (h === e || h.endsWith('.' + e));
  });
}

/**
 * Classify a lockfile `resolved` value. Returns null when the source is
 * expected (allowlisted registry, public git forge, monorepo link, or a bare
 * registry-relative specifier with no protocol).
 */
export function classifyResolved(resolved, allowed = DEFAULT_ALLOWED_REGISTRIES) {
  if (!resolved || typeof resolved !== 'string') {
    return null;
  }
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(resolved)) {
    return null; // "/foo@1.0.0", "foo@1.0.0" — registry-relative, not off-registry
  }
  let url;
  try {
    url = new URL(resolved);
  } catch {
    return null;
  }
  const proto = url.protocol.replace(':', '').toLowerCase();
  if (proto === 'link' || proto === 'workspace') {
    return null; // monorepo local linking
  }
  const host = (url.hostname || '').toLowerCase();

  if (proto === 'http') {
    return {
      kind: 'cleartext',
      host,
      severity: 'high',
      detail: `dependency fetched over cleartext http: ${resolved}`,
    };
  }
  if (proto === 'git+ssh' || proto === 'ssh') {
    return {
      kind: 'ssh',
      host,
      severity: 'high',
      detail: `dependency fetched over ssh (no registry integrity path): ${resolved}`,
    };
  }
  if (proto === 'file') {
    return {
      kind: 'file',
      host,
      severity: 'medium',
      detail: `dependency resolved to a local file path: ${resolved}`,
    };
  }
  if (proto === 'https' || proto === 'git+https') {
    if (hostMatchesAllowlist(host, allowed) || KNOWN_GIT_HOSTS.has(host)) {
      return null;
    }
    return {
      kind: 'off_registry',
      host,
      severity: 'medium',
      detail: `unexpected registry host "${host}": ${resolved}`,
    };
  }
  return {
    kind: 'odd_protocol',
    host,
    severity: 'medium',
    detail: `unusual resolved protocol "${proto}": ${resolved}`,
  };
}

/**
 * Findings for off-registry/insecure `resolved` sources and for entries that
 * resolve a tarball with no `integrity` hash.
 */
export function analyzeResolutionIntegrity(lockfileData, options = {}) {
  const allowed = [...DEFAULT_ALLOWED_REGISTRIES, ...(options.allowedRegistries || [])];
  const hostIssues = new Map();
  const missingIntegrity = [];

  for (const pkg of lockfileData.packages || []) {
    const label = `${pkg.name}@${pkg.version}`;
    const cls = classifyResolved(pkg.resolved, allowed);
    if (cls) {
      const key = `${cls.kind}:${cls.host}`;
      if (!hostIssues.has(key)) {
        hostIssues.set(key, { ...cls, pkgs: [] });
      }
      hostIssues.get(key).pkgs.push(label);
    }
    if (pkg.resolved && !pkg.integrity) {
      missingIntegrity.push(label);
    }
  }

  const findings = [];
  const listSuffix = (arr) =>
    `${arr.slice(0, 10).join(', ')}${arr.length > 10 ? ` (+${arr.length - 10} more)` : ''}`;

  for (const cls of hostIssues.values()) {
    findings.push({
      id: 'LOCKFILE-RESOLVED-HOST',
      severity: cls.severity,
      title: 'Dependency resolves from an off-registry or insecure source',
      description: cls.detail,
      evidence: `packages: ${listSuffix(cls.pkgs)}`,
    });
  }

  if (missingIntegrity.length > 0) {
    findings.push({
      id: 'LOCKFILE-MISSING-INTEGRITY',
      severity: 'medium',
      title: 'Lockfile entries lack an integrity hash',
      description: `${missingIntegrity.length} entr${missingIntegrity.length === 1 ? 'y resolves' : 'ies resolve'} a tarball with no integrity field, removing the tamper check the package manager would otherwise enforce.`,
      evidence: `packages: ${listSuffix(missingIntegrity)}`,
    });
  }

  return findings;
}

export function parseLockfile(filePath, options = {}) {
  const { autoDetect = false } = options;
  try {
    const content = readFileSync(filePath, 'utf8');
    const ext = filePath.split('.').pop().toLowerCase();

    if (ext === 'json' || ext === 'jsonc') {
      return parseNpmLockfile(content, filePath);
    }
    if (ext === 'lock' && !autoDetect) {
      return parseYarnLockfile(content, filePath);
    }
    if (ext === 'yaml' || ext === 'yml') {
      return parsePnpmLockfile(content, filePath);
    }

    if (autoDetect) {
      if (content.trimStart().startsWith('{')) {
        return parseNpmLockfile(content, filePath);
      }
      if (content.includes('__metadata')) {
        return parsePnpmLockfile(content, filePath);
      }
      if (content.includes('@npm:') || /^\s*"?[\w@/-]+['"]?\s*,\s*$/m.test(content)) {
        return parseYarnLockfile(content, filePath);
      }
    }

    return parseNpmLockfile(content, filePath);
  } catch (e) {
    throw new Error(`Failed to parse lockfile: ${e.message}`, { cause: e });
  }
}

function parseNpmLockfile(content, _filePath) {
  const lockfile = JSON.parse(content);
  const packages = [];

  if (lockfile.packages) {
    for (const [key, pkg] of Object.entries(lockfile.packages)) {
      if (key === '') {
        continue;
      }
      const name = pkg.name || key.replace(/^node_modules\//, '').replace(/^[^/]+\//, '');
      packages.push({
        name,
        version: pkg.version || 'unknown',
        resolved: pkg.resolved || '',
        integrity: pkg.integrity || '',
        path: key,
        peerDeps: pkg.peerDependencies || {},
        dev: pkg.dev || false,
        optional: pkg.optional || false,
        scripts: pkg.scripts || {},
        dependencies: pkg.dependencies || {},
      });
    }
  }

  const rootDeps = lockfile.packages?.['node_modules/'] || {};
  return {
    version: lockfile.lockfileVersion,
    packages,
    root: {
      name: rootDeps.name || 'unknown',
      version: rootDeps.version || 'unknown',
      dependencies: rootDeps.dependencies || {},
      devDependencies: rootDeps.devDependencies || {},
      peerDependencies: rootDeps.peerDependencies || {},
    },
  };
}

function parseYarnLockfile(content, _filePath) {
  const packages = [];
  const lines = content.split('\n');
  let i = 0;
  const n = lines.length;

  const MULTI_ENTRY_RE =
    /^"?([\w@./-]+)@(\^?[\w.+\-~]+)"?\s*,\s*"?([\w@./-]+)@(\^?[\w.+\-~]+)"?\s*:\s*$/;
  const SINGLE_ENTRY_RE = /^"?([\w@./-]+)@(\^?[\w.+\-~]+)"?\s*:\s*$/;

  while (i < n) {
    const line = lines[i].trimEnd();

    let specs = [];

    const multiMatch = line.match(MULTI_ENTRY_RE);
    const singleMatch = line.match(SINGLE_ENTRY_RE);

    if (multiMatch) {
      specs = [
        { name: multiMatch[1], specVersion: multiMatch[2] },
        { name: multiMatch[3], specVersion: multiMatch[4] },
      ];
    } else if (singleMatch) {
      specs = [{ name: singleMatch[1], specVersion: singleMatch[2] }];
    }

    if (specs.length > 0) {
      let version = '';
      let resolved = '';
      let integrity = '';
      const dependencies = {};
      const optionalDependencies = {};
      const peerDependencies = {};
      let dev = false;
      let optional = false;

      i++;
      while (i < n) {
        const bodyLine = lines[i];
        const bodyTrim = bodyLine.trimEnd();

        if (bodyTrim === '' || bodyTrim.startsWith('#')) {
          i++;
          continue;
        }

        if (bodyTrim.endsWith(':') && !bodyLine.startsWith(' ')) {
          break;
        }

        if (bodyTrim.startsWith('version ')) {
          const vMatch = bodyTrim.match(/^version ['"]([^'"]+)['"]/);
          if (vMatch) {
            version = vMatch[1];
          }
        } else if (bodyTrim.match(/^\s*resolved\s+(.+)/)) {
          const rMatch = bodyTrim.match(/^\s*resolved\s+(.+)/);
          if (rMatch) {
            resolved = rMatch[1].trim().replace(/^['"]|['"]$/g, '');
            if (resolved.startsWith('https://registry.yarnpkg.com/')) {
              resolved = resolved.replace(
                'https://registry.yarnpkg.com/',
                'https://registry.npmjs.org/'
              );
            }
          }
        } else if (bodyTrim.startsWith('integrity ')) {
          integrity = bodyTrim.replace('integrity ', '').trim();
        } else if (bodyTrim.startsWith('dependencies')) {
          const m = bodyTrim.match(/^dependencies\s+(.*)/);
          if (m) {
            parseDepList(m[1], dependencies);
          }
        } else if (bodyTrim.startsWith('optionalDependencies')) {
          const m = bodyTrim.match(/^optionalDependencies\s+(.*)/);
          if (m) {
            parseDepList(m[1], optionalDependencies);
          }
        } else if (bodyTrim.startsWith('peerDependencies')) {
          const m = bodyTrim.match(/^peerDependencies\s+(.*)/);
          if (m) {
            parseDepList(m[1], peerDependencies);
          }
        } else if (bodyTrim.match(/^\s*dev\s+(true|false)$/)) {
          dev = bodyTrim.includes('true');
        } else if (bodyTrim.match(/^\s*optional\s+(true|false)$/)) {
          optional = bodyTrim.includes('true');
        }

        i++;
      }

      for (const { name, specVersion } of specs) {
        packages.push({
          name,
          version: version || specVersion,
          resolved,
          integrity,
          path: `node_modules/${name}`,
          peerDeps: peerDependencies,
          dev,
          optional,
          scripts: {},
          dependencies,
          optionalDependencies,
        });
      }
    } else {
      i++;
    }
  }

  const rootDeps = {};
  const rootDevDeps = {};

  for (const pkg of packages) {
    const topDeps = pkg.dev ? rootDevDeps : rootDeps;
    for (const depName of Object.keys(pkg.dependencies)) {
      topDeps[depName] = pkg.dependencies[depName];
    }
  }

  return {
    version: 2,
    packages,
    root: {
      name: 'root',
      version: 'unknown',
      dependencies: rootDeps,
      devDependencies: rootDevDeps,
      peerDependencies: {},
    },
  };
}

function parseDepList(str, dest) {
  const cleaned = str.replace(/^[[\]]/g, '').trim();
  if (!cleaned) {
    return;
  }
  const re = /([\w@./-]+)\s+\^?([\w@./-]+)/g;
  let m;
  while ((m = re.exec(cleaned)) !== null) {
    dest[m[1]] = m[2];
  }
}

function parsePnpmLockfile(content, _filePath) {
  const lockfile = yaml.load(content);
  const packages = [];

  if (lockfile.packages) {
    for (const [key, pkg] of Object.entries(lockfile.packages)) {
      const nameMatch = key.match(/^\/(.+?)@([^@/]+)$/);
      if (!nameMatch) {
        continue;
      }
      const name = nameMatch[1];
      const version = nameMatch[2];

      const resolved = pkg.resolution?.url || '';
      let integrity = '';
      if (pkg.resolution?.integrity) {
        integrity = pkg.resolution.integrity;
      } else if (pkg.resolution?.sha512) {
        integrity = `sha512-${pkg.resolution.sha512}`;
      }

      packages.push({
        name,
        version,
        resolved,
        integrity,
        path: `node_modules/${name}`,
        peerDeps: pkg.peerDependencies || {},
        dev: pkg.dev || false,
        optional: pkg.optional || false,
        scripts: pkg.hasBundledMedia ? { bundled: true } : {},
        dependencies: pkg.dependencies || {},
        optionalDependencies: pkg.optionalDependencies || {},
      });
    }
  }

  const rootDeps = lockfile.importers?.['.'] || lockfile.root || {};
  const rootDepsMap = rootDeps.dependencies || {};
  const rootDevDepsMap = rootDeps.devDependencies || {};
  const rootPeerDepsMap = rootDeps.peerDependencies || {};

  const version = lockfile.version || (lockfile.lockfileVersion ?? 6);

  return {
    version,
    packages,
    root: {
      name: 'root',
      version: lockfile.lockfileVersion ? 'unknown' : 'unknown',
      dependencies: rootDepsMap,
      devDependencies: rootDevDepsMap,
      peerDependencies: rootPeerDepsMap,
    },
  };
}

export function checkMaliciousPatterns(pkg) {
  const findings = [];
  const name = pkg.name?.toLowerCase() || '';

  const typosquatPatterns = [
    /^(lodash|lodahs|lodash-js|lodashexe)$/,
    /^(axios|axio|ax10s|ax1os)$/,
    /^(react|reakt|reackt|r3act)$/,
    /^(express|expres|expresjs|exress)$/,
    /^(vue|vu3|vujs|vuejs)$/,
    /^(webpack|webpak|webpackjs)$/,
  ];

  for (const pattern of typosquatPatterns) {
    if (pattern.test(name)) {
      findings.push({
        id: 'ATK-007',
        severity: 'high',
        title: 'Typosquat detected',
        description: `Package name "${pkg.name}" is similar to popular packages`,
        evidence: `similar to ${pattern.source}`,
      });
    }
  }

  return findings;
}

export function analyzeDependencyGraph(lockfileData) {
  const findings = [];
  const pkgMap = new Map();

  for (const pkg of lockfileData.packages) {
    pkgMap.set(pkg.name, pkg);
  }

  for (const pkg of lockfileData.packages) {
    if (pkg.peerDeps && Object.keys(pkg.peerDeps).length > 0) {
      for (const [peerName, peerVersion] of Object.entries(pkg.peerDeps)) {
        if (peerName.includes('plugin') || peerName.includes('hook') || peerName.includes('ext')) {
          findings.push({
            id: 'ATK-011',
            severity: 'high',
            title: 'Transitive propagation (worm)',
            description: `Package "${pkg.name}" depends on peer "${peerName}@${peerVersion}" - potential worm propagation chain`,
            evidence: `peer dep chain: ${pkg.name} -> ${peerName}`,
          });
        }
      }
    }

    if (
      pkg.dependencies &&
      typeof pkg.dependencies === 'object' &&
      Object.keys(pkg.dependencies).length > 5
    ) {
      const transitiveCount = Object.keys(pkg.dependencies).filter((k) => k.includes('/')).length;
      if (transitiveCount > 3) {
        findings.push({
          id: 'ATK-011',
          severity: 'medium',
          title: 'Transitive propagation (worm)',
          description: `Package "${pkg.name}" has excessive transitive dependencies (${transitiveCount} scoped)`,
          evidence: `heavy transitive dep chain: ${pkg.name}`,
        });
      }
    }

    if (pkg.optionalDependencies && Object.keys(pkg.optionalDependencies).length > 10) {
      findings.push({
        id: 'ATK-011',
        severity: 'low',
        title: 'Transitive propagation (worm)',
        description: `Package "${pkg.name}" has excessive optional dependencies (${Object.keys(pkg.optionalDependencies).length})`,
        evidence: `optional dep chain: ${pkg.name} -> [${Object.keys(pkg.optionalDependencies).slice(0, 3).join(', ')}, ...]`,
      });
    }
  }

  return findings;
}

export function generateLockfileReport(lockfileData, options = {}) {
  const total = lockfileData.packages.length;
  const dev = lockfileData.packages.filter((p) => p.dev).length;
  const optional = lockfileData.packages.filter((p) => p.optional).length;

  const findings = [];

  for (const pkg of lockfileData.packages) {
    const maliciousFindings = checkMaliciousPatterns(pkg);
    findings.push(...maliciousFindings);
  }

  findings.push(...analyzeDependencyGraph(lockfileData));
  findings.push(...analyzeResolutionIntegrity(lockfileData, options));

  return {
    scanId: Date.now(),
    package: lockfileData.root.name,
    version: lockfileData.root.version,
    totalDependencies: total,
    devDependencies: dev,
    optionalDependencies: optional,
    lockfileVersion: lockfileData.version,
    findings,
    riskScore: calculateRiskScore(findings),
  };
}

function calculateRiskScore(findings) {
  if (!findings.length) {
    return '0.0';
  }
  const weights = { critical: 10, high: 7, medium: 4, low: 2, info: 0.5 };
  const maxSeverity = findings.reduce((max, f) => {
    const w = weights[f.severity] || 0;
    return Math.max(max, w);
  }, 0);
  const countBonus = Math.min(findings.length * 0.3, 3);
  const score = Math.min(maxSeverity + countBonus, 10);
  return score.toFixed(1);
}
