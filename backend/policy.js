import { readFileSync } from 'fs';
import { load as yamlLoad } from 'js-yaml';

const SEVERITY_ORDER = ['none', 'low', 'medium', 'high', 'critical'];
const VALID_SEVERITIES = new Set(SEVERITY_ORDER);

const KNOWN_REPUTABLE_PACKAGES = new Set([
  'react', 'react-dom', 'vue', 'angular', 'next', 'nuxt',
  'express', 'fastify', 'hono', 'koa', 'connect',
  'webpack', 'vite', 'rollup', 'esbuild', 'typescript', 'babel-core',
  'lodash', 'ramda', 'underscore',
  'axios', 'node-fetch', 'got', 'superagent',
  'sequelize', 'prisma', 'typeorm', 'mongoose',
  'jest', 'mocha', 'vitest', 'ava',
  'prettier', 'eslint', 'stylelint',
  'socket.io', 'ws',
  'rimraf', 'glob', 'minimatch', 'fs-extra',
]);

function severityIndex(s) {
  return SEVERITY_ORDER.indexOf(s);
}

function matchesFilePath(filePath, pattern) {
  if (!pattern) return false;
  if (pattern === '*') return true;
  const regexPattern = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '___DOUBLE_STAR___')
    .replace(/\*/g, '[^/]*')
    .replace(/___DOUBLE_STAR___/g, '.*');
  return new RegExp(`^${regexPattern}$`).test(filePath);
}

function matchesContext(finding, rule) {
  const ctx = finding.context;
  if (!ctx) return false;

  if (rule.context?.is_dist_build === true && !ctx.is_dist_build) return false;
  if (rule.context?.is_dist_build === false && ctx.is_dist_build) return false;
  if (rule.context?.is_test_fixture === true && !ctx.is_test_fixture) return false;
  if (rule.context?.is_test_fixture === false && ctx.is_test_fixture) return false;
  if (rule.context?.is_lifecycle_hook === true && !ctx.is_lifecycle_hook) return false;
  if (rule.context?.is_lifecycle_hook === false && ctx.is_lifecycle_hook) return false;
  if (rule.context?.is_known_safe_domain === true && !ctx.is_known_safe_domain) return false;
  if (rule.context?.is_known_safe_domain === false && ctx.is_known_safe_domain) return false;

  if (rule.context?.file_path && !matchesFilePath(ctx.file_path, rule.context.file_path)) return false;
  if (rule.context?.url_domain) {
    if (!ctx.url_domain) return false;
    const domainPattern = rule.context.url_domain.replace(/\*/g, '.*');
    if (!new RegExp(`^${domainPattern}$`).test(ctx.url_domain)) return false;
  }

  return true;
}

function getPackageReputationTier(pkgName) {
  const name = pkgName?.replace(/^@/, '').replace(/\/.*/, '') || '';
  if (KNOWN_REPUTABLE_PACKAGES.has(name)) return 'trusted';
  return 'unknown';
}

function matchesSuppressRule(finding, pkgName, rule) {
  if (rule.atk_id !== (finding.atk_id || finding.id)) return false;
  if (rule.package && rule.package !== '*' && rule.package !== pkgName) return false;

  if (rule.context && !matchesContext(finding, rule)) return false;

  if (rule.reputation_tier) {
    const tier = getPackageReputationTier(pkgName);
    if (rule.reputation_tier !== tier && !(rule.reputation_tier === '*' || rule.reputation_tier === 'any')) return false;
  }

  return true;
}

function loadPolicy(path) {
  const raw = readFileSync(path, 'utf8').trim();
  let policy;

  if (path.endsWith('.json')) {
    policy = JSON.parse(raw);
  } else {
    policy = yamlLoad(raw);
  }

  if (!policy || typeof policy !== 'object') {
    throw new Error('Policy file must contain a valid YAML/JSON object');
  }

  if (policy.severity_overrides) {
    for (const [atkId, severity] of Object.entries(policy.severity_overrides)) {
      if (!VALID_SEVERITIES.has(severity)) {
        throw new Error(`Invalid severity "${severity}" for ${atkId} — must be one of: low, medium, high, critical`);
      }
    }
  }

  if (policy.fail_on && !VALID_SEVERITIES.has(policy.fail_on)) {
    throw new Error(`Invalid fail_on "${policy.fail_on}" — must be one of: none, low, medium, high, critical`);
  }

  if (policy.suppress) {
    if (!Array.isArray(policy.suppress)) {
      throw new Error('suppress must be an array');
    }
    for (const rule of policy.suppress) {
      if (!rule.atk_id) {
        throw new Error('Each suppress rule must have an atk_id');
      }
    }
  }

  if (policy.allow) {
    if (policy.allow.packages && !Array.isArray(policy.allow.packages)) {
      throw new Error('allow.packages must be an array');
    }
  }

  return sanitizePolicy(policy);
}

function sanitizePolicy(policy) {
  return {
    allow: { packages: policy.allow?.packages ?? [] },
    severity_overrides: policy.severity_overrides ?? {},
    fail_on: policy.fail_on ?? 'none',
    suppress: (policy.suppress ?? []).map(r => ({
      atk_id: r.atk_id,
      package: r.package || '*',
      reason: r.reason || '',
      context: r.context || null,
      reputation_tier: r.reputation_tier || null,
    })),
  };
}

function isAllowed(packageName, policy) {
  if (!policy.allow.packages.length) return false;
  const nameOnly = packageName.split('@')[0];
  return policy.allow.packages.some(p => p === packageName || p === nameOnly);
}

function applyPolicy(findings, packageName, policy) {
  let filtered = [...findings];

  if (policy.suppress.length) {
    filtered = filtered.filter(f => {
      if (f.context?.is_lifecycle_hook) return true;
      if (f.context?.is_multi_layer) return true;
      return !policy.suppress.some(r => matchesSuppressRule(f, packageName, r));
    });
  }

  filtered = filtered.map(f => {
    const override = policy.severity_overrides[f.atk_id || f.id];
    if (override) {
      return { ...f, severity: override, _severityOverridden: true };
    }
    return f;
  });

  const blocked = checkFailOn(filtered, policy);

  return { findings: filtered, blocked };
}

function checkFailOn(findings, policy) {
  if (policy.fail_on === 'none') return false;

  const threshold = severityIndex(policy.fail_on);
  return findings.some(f => severityIndex(f.severity) >= threshold);
}

export { loadPolicy, applyPolicy, isAllowed, getPackageReputationTier, matchesContext };
