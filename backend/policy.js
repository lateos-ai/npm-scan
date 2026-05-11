import { readFileSync } from 'fs';
import { load as yamlLoad } from 'js-yaml';

const SEVERITY_ORDER = ['none', 'low', 'medium', 'high', 'critical'];
const VALID_SEVERITIES = new Set(SEVERITY_ORDER);

function severityIndex(s) {
  return SEVERITY_ORDER.indexOf(s);
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
    })),
  };
}

function isAllowed(packageName, policy) {
  if (!policy.allow.packages.length) return false;
  const nameOnly = packageName.split('@')[0];
  return policy.allow.packages.some(p => p === packageName || p === nameOnly);
}

function matchesSuppressRule(finding, pkgName, rule) {
  if (rule.atk_id !== (finding.atk_id || finding.id)) return false;
  if (rule.package === '*') return true;
  return rule.package === pkgName;
}

function applyPolicy(findings, packageName, policy) {
  let filtered = [...findings];

  if (policy.suppress.length) {
    filtered = filtered.filter(f =>
      !policy.suppress.some(r => matchesSuppressRule(f, packageName, r))
    );
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

export { loadPolicy, applyPolicy, isAllowed };
