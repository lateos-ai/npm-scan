export async function scan(pkgJson, files = []) {
  const findings = [];
  const code = files.map(f => f.content).join('\n');
  if (/curl.*(-d|--data|--data-binary)|github\.com\/.*keys|pastebin|dns\.resolve.*\.com|exfil/.test(code.toLowerCase())) {
    findings.push({
      id: 'ATK-005',
      severity: 'critical',
      title: 'Network exfiltration',
      description: 'Suspicious network calls: curl data exfil, pastebin, dns tunneling',
      evidence: 'network exfil pattern'
    });
  }
  return findings;
}