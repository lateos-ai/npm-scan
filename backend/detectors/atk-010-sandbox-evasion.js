export async function scan(pkgJson, files = []) {
  const findings = [];
  const code = files.map(f => f.content).join('\n');

  const highPatterns = [
    { pattern: /\bdebugger\s*;?(\s*\/\/|\s*$|\)|\])/m, label: 'debugger statement' },
    { pattern: /process\.argv.*['"]--inspect['"]|process\.argv.*\binspect\b(?!.*argv)/, label: 'inspect/debug flag detection' },
    { pattern: /hostname.*(?:docker|sandbox|container|vmware|vbox)/i, label: 'anti-sandbox hostname check' },
    { pattern: /detect.*(?:sandbox|debugger|analysis|virtual)/i, label: 'explicit evasion probe' },
    { pattern: /e\.stack\b.*(?:sandbox|docker|container|vmware)/i, label: 'stack trace sandbox probe' },
  ];

  for (const { pattern, label } of highPatterns) {
    if (pattern.test(code)) {
      findings.push({
        id: 'ATK-010',
        severity: 'high',
        title: 'Sandbox evasion / anti-analysis',
        description: `Package performs anti-analysis behavior: ${label}`,
        evidence: 'evasion pattern detected'
      });
      break;
    }
  }

  if (findings.length === 0) {
    const multiApi = ['process.pid', 'process.ppid', 'os.hostname', 'os.cpus', 'process.arch'].filter(api => code.includes(api));
    if (multiApi.length >= 3) {
      findings.push({
        id: 'ATK-010',
        severity: 'medium',
        title: 'Sandbox evasion / anti-analysis',
        description: 'Multiple system fingerprinting APIs detected',
        evidence: `${multiApi.length} fingerprinting APIs: ${multiApi.join(', ')}`
      });
    }
  }

  const multiStack = ['Error().stack', 'new Error().stack'].filter(s => code.includes(s));
  if (multiStack.length > 0 && /atob|eval|execSync|spawn|child_process/.test(code)) {
    findings.push({
      id: 'ATK-010',
      severity: 'medium',
      title: 'Sandbox evasion / anti-analysis',
      description: 'Stack trace capture combined with code execution',
      evidence: 'stack trace + execution'
    });
  }

  return findings;
}