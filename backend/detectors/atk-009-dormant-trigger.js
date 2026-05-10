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

  const timePatterns = [
    { pattern: /new Date\(\)\s*[><=!]+\s*new Date\(['"]\d{4}/, label: 'time-based activation' },
    { pattern: /Date\.now\(\)\s*[><=!]+/, label: 'timestamp comparison' },
    { pattern: /setTimeout|setInterval/, label: 'delayed execution' },
    { pattern: /\bDate\(\)\b.*\d{4}[-/]\d{2}[-/]\d{2}/, label: 'date-specific payload' },
  ];

  for (const { pattern, label } of timePatterns) {
    if (pattern.test(code)) {
      findings.push({
        id: 'ATK-009',
        severity: 'medium',
        title: 'Conditional trigger (time-based)',
        description: `Package has ${label} which may indicate dormant activation`,
        evidence: 'time-based trigger detected'
      });
      break;
    }
  }

  return findings;
}