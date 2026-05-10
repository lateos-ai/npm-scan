export async function scan(pkgJson, files = []) {
  const findings = [];
  const code = files.map(f => f.content).join('\n');
  if (/process\.env\.(NPM_TOKEN|GIT_TOKEN|AWS_SECRET|AWS_ACCESS|SSH_KEY)|\.npmrc|\.ssh\/id_rsa|readFile.*\.ssh/.test(code)) {
    findings.push({
      id: 'ATK-003',
      severity: 'high',
      title: 'Credential harvesting',
      description: 'Env vars or .npmrc/SSH key access',
      evidence: 'credential pattern match'
    });
  }
  return findings;
}