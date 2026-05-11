export async function scan(pkgJson, files = []) {
  const findings = [];
  const code = files.map(f => f.content).join('\n');

  const ciPatterns = [
    { pattern: /process\.env\.CI\b/, label: 'CI env check' },
    { pattern: /process\.env\.(TRAVIS|CIRCLECI|GITHUB_ACTIONS|JENKINS|GITLAB_CI|CODEBUILD)/, label: 'CI platform check' },
    { pattern: /\bisCI\b/, label: 'isCI utility check' },
  ];

  for (const { pattern, label } of ciPatterns) {
    if (pattern.test(code)) {
      findings.push({
        id: 'ATK-009',
        severity: 'high',
        title: 'Conditional trigger (CI/production env)',
        description: `Package checks for CI or production environment: ${label}`,
        evidence: 'conditional trigger detected'
      });
      break;
    }
  }

  const suspiciousCode = /\beval\(|atob\(|btoa\(|new Function\(|child_process\b|\.exec\(|spawn\(/;
  const suspiciousNetwork = /\.fetch\(|http\.request\(|https\.request\(|dns\.lookup\(/;
  const suspiciousEnv = /process\.env\.(?!NODE_ENV)[A-Z_]{4,}/;
  const hasSuspicious = suspiciousCode.test(code) || suspiciousNetwork.test(code) || suspiciousEnv.test(code);

  const timePatterns = [
    {
      pattern: /new Date\(\)\s*[><=!]+\s*new Date\(['"]\d{4}/,
      label: 'time-based activation',
    },
    {
      pattern: /\bDate\.now\(\)\s*[><=!]+.*(?:eval|fetch|exec|write|crypto|env\.CI)/i,
      label: 'timestamp check with suspicious behavior',
    },
    {
      pattern: /\bsetTimeout\s*\([^)]*,\s*(?!0\b)[1-9]\d{3,}/,
      label: 'long-delay execution (>1000ms)',
    },
    {
      pattern: /\bDate\(\)\b.*(?:exec|eval|fetch|write|crypto)/i,
      label: 'date check with suspicious behavior',
    },
  ];

  for (const { pattern, label } of timePatterns) {
    if (pattern.test(code)) {
      findings.push({
        id: 'ATK-009',
        severity: hasSuspicious ? 'high' : 'medium',
        title: 'Conditional trigger (time-based)',
        description: `Package uses ${label}`,
        evidence: `${label}${hasSuspicious ? ' — elevated (suspicious context: eval/network/exec detected)' : ''}`
      });
      break;
    }
  }

  return findings;
}
