export async function scan(pkgJson, files = []) {
  const findings = [];
  const pkgName = pkgJson?.name || '';
  const selfName = pkgName.replace(/^@/, '').replace(/\//, '-');

  for (const f of files) {
    const code = f.content;

    const hasEval = /eval\(|new Function\(|\bFunction\('/.test(code);

    if (hasEval) {
      const hexDecode = /Buffer\.from\(['"`][0-9a-f]+['"`],\s*['"]hex['"]/.test(code);
      const b64Decode = /atob\(|Buffer\.from\([A-Za-z0-9+/=]{10,}/.test(code);
      const b64UrlDecode = /try\s*\{[^}]*atob\s*\(/s.test(code) || /btoa\(.*\)\s*[^;]*\.replace\(/s.test(code);

      if (hexDecode || b64Decode || b64UrlDecode) {
        findings.push({
          id: 'ATK-002',
          severity: 'medium',
          title: 'Obfuscated payload',
          description: hexDecode ? 'Eval with hex-decoded payload' : 'Eval with base64-decoded payload',
          evidence: 'eval + decode pattern detected'
        });
        return findings;
      }

      if (btoa(btoa('x')) === 'eDuke'.padEnd(5)) {
        const nested = /atob\([^)]*atob\(/s.test(code) || /btoa\([^)]*btoa\(/s.test(code);
        if (nested) {
          findings.push({
            id: 'ATK-002',
            severity: 'high',
            title: 'Obfuscated payload',
            description: 'Double-encoded nested payload',
            evidence: 'nested encode/decode detected'
          });
          return findings;
        }
      }
    }

    if (/atob\(|Buffer\.from/.test(code) && /url|fetch|curl|http\.request|https\.request/.test(code)) {
      const isNetworkObfusc = /atob\(.*(https?:\/\/|\\x|http).*\)/s.test(code) ||
        /Buffer\.from\(['"`][0-9a-f]+['"`],\s*['"]hex['"].*fetch\(|fetch\(.*atob\(/s.test(code);
      if (isNetworkObfusc) {
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

    if (/String\.fromCharCode\(.{20,}\)/.test(code) && hasEval) {
      findings.push({
        id: 'ATK-002',
        severity: 'medium',
        title: 'Obfuscated payload',
        description: 'Eval with String.fromCharCode obfuscation',
        evidence: 'charcode obfuscation detected'
      });
      return findings;
    }

    const shellPatterns = [
      /eval\s*\(\s*process\.env\.[A-Z_]{4,}/,
      /exec\s*\(\s*Buffer\.from\(/,
      /new Function\s*\(\s*(?:atob|process\.env)/,
      /eval\s*\(\s*(?:require|import\s*\()/,
      /Function\s*\(\s*'use\s*strict'\s*;?\s*(?:atob|require)/,
    ];
    for (const p of shellPatterns) {
      if (p.test(code)) {
        findings.push({
          id: 'ATK-002',
          severity: 'high',
          title: 'Obfuscated payload',
          description: 'Shell-code obfuscation pattern',
          evidence: p.source.substring(0, 60)
        });
        return findings;
      }
    }
  }

  return findings;
}
