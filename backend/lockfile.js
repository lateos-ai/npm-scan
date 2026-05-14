import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

export function parseLockfile(filePath) {
  try {
    const content = readFileSync(filePath, 'utf8');
    const lockfile = JSON.parse(content);
    const packages = [];

    if (lockfile.packages) {
      for (const [key, pkg] of Object.entries(lockfile.packages)) {
        if (key === '') continue;
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
          dependencies: pkg.dependencies || {}
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
        peerDependencies: rootDeps.peerDependencies || {}
      }
    };
  } catch (e) {
    throw new Error(`Failed to parse lockfile: ${e.message}`);
  }
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
        evidence: `similar to ${pattern.source}`
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
            evidence: `peer dep chain: ${pkg.name} -> ${peerName}`
          });
        }
      }
    }

    if (pkg.dependencies && Object.keys(pkg.dependencies).length > 5) {
      const transitiveCount = [...pkg.dependencies].filter(([k]) => k.includes('scope')).length;
      if (transitiveCount > 3) {
        findings.push({
          id: 'ATK-011',
          severity: 'medium',
          title: 'Transitive propagation (worm)',
          description: `Package "${pkg.name}" has excessive transitive dependencies (${transitiveCount} scoped)`,
          evidence: `heavy transitive dep chain: ${pkg.name}`
        });
      }
    }
  }

  return findings;
}

export function generateLockfileReport(lockfileData) {
  const total = lockfileData.packages.length;
  const dev = lockfileData.packages.filter(p => p.dev).length;
  const optional = lockfileData.packages.filter(p => p.optional).length;

  const findings = [];

  for (const pkg of lockfileData.packages) {
    const maliciousFindings = checkMaliciousPatterns(pkg);
    findings.push(...maliciousFindings);
  }

  findings.push(...analyzeDependencyGraph(lockfileData));

  return {
    scanId: Date.now(),
    package: lockfileData.root.name,
    version: lockfileData.root.version,
    totalDependencies: total,
    devDependencies: dev,
    optionalDependencies: optional,
    lockfileVersion: lockfileData.version,
    findings,
    riskScore: calculateRiskScore(findings)
  };
}

function calculateRiskScore(findings) {
  if (!findings.length) return '0.0';
  const weights = { critical: 10, high: 7, medium: 4, low: 2, info: 0.5 };
  const maxSeverity = findings.reduce((max, f) => {
    const w = weights[f.severity] || 0;
    return Math.max(max, w);
  }, 0);
  const countBonus = Math.min(findings.length * 0.3, 3);
  const score = Math.min(maxSeverity + countBonus, 10);
  return score.toFixed(1);
}