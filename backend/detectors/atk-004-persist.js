export async function scan(pkgJson, files = []) {
  const findings = [];
  const code = files.map(f => f.content).join('\n');
  if (/mkdir.*(\.vscode|\.claude|\.cursor)/.test(code)) {
    findings.push({
      id: 'ATK-004',
      severity: 'high',
      title: 'Persistence via editor configs',
      description: 'Creates .vscode/.claude/.cursor dirs',
      evidence: 'mkdir pattern match'
    });
  }
  return findings;
}