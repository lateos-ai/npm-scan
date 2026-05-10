export async function scan(pkgJson, files = []) {
  const findings = [];
  for (const f of files) {
    const code = f.content;
    const hasEval = /eval\(/.test(code);
    const hasDecode = /atob\(|Buffer\.from\(.*(?:base64|hex)/i.test(code);
    if (hasEval && hasDecode) {
      findings.push({
        id: 'ATK-002',
        severity: 'medium',
        title: 'Obfuscated payload',
        description: 'Eval with base64/hex/Buffer.from payload',
        evidence: 'obfuscation detected'
      });
      return findings;
    }
    if (/atob\(|Buffer\.from/.test(code) && /url|fetch|curl|http:|https:/.test(code)) {
      findings.push({
        id: 'ATK-002',
        severity: 'medium',
        title: 'Obfuscated payload',
        description: 'Decoded string containing URL/fetch call',
        evidence: 'obfuscation with network call'
      });
      return findings;
    }
  }
  return findings;
}