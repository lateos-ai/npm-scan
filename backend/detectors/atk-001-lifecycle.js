export async function scan(pkgJson, files = []) {
  const findings = [];
  const scripts = pkgJson.scripts || {};
  const suspicious = Object.keys(scripts).filter(s => /pre|post|install/i.test(s));
  if (suspicious.length) {
    const content = suspicious.map(s => scripts[s]).join(' ');
    if (/curl|wget|sh |bash |\.sh|exfil|steal|pwn|c2|pastebin/i.test(content)) {
      findings.push({
        id: 'ATK-001',
        severity: 'high',
        title: 'Malicious lifecycle scripts',
        description: 'Suspicious install hooks',
        evidence: suspicious.join(', ')
      });
    }
  }
  return findings;
}