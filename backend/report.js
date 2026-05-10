export function generateHTML(scans) {
  const rows = scans.map(s => {
    const findings = s.findings || [];
    const sevMap = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const worst = findings.reduce((m, f) => Math.max(m, sevMap[f.severity] || 0), 0);
    const worstLabel = ['', 'info', 'low', 'medium', 'high', 'critical'][worst] || 'clean';
    const color = { critical: '#d73a49', high: '#cb2431', medium: '#f66a0a', low: '#dbab09', clean: '#28a745' }[worstLabel] || '#28a745';
    const findingRows = findings.map(f =>
      `<tr><td>${f.id}</td><td style="color:${color}">${f.severity}</td><td>${f.title || ''}</td><td>${f.evidence || ''}</td></tr>`
    ).join('');
    return { name: s.package_name, worstLabel, color, count: findings.length, findingRows };
  });

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>npm-scan Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
h2 { color: #8b949e; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; }
th { background: #161b22; font-weight: 600; }
.summary { display: flex; gap: 16px; margin: 16px 0; }
.badge { padding: 4px 12px; border-radius: 12px; font-size: 13px; font-weight: 600; }
.critical { background: #d73a49; color: #fff; }
.high { background: #cb2431; color: #fff; }
.medium { background: #f66a0a; color: #fff; }
.low { background: #dbab09; color: #000; }
.clean { background: #28a745; color: #fff; }
.meta { color: #8b949e; font-size: 13px; margin-top: 30px; }
</style>
</head>
<body>
<h1>npm-scan Report</h1>
<p>Generated ${new Date().toISOString()}. ${scans.length} packages scanned.</p>

<div class="summary">
<div class="badge critical">critical: ${scans.filter(s => s.worstLabel === 'critical').length}</div>
<div class="badge high">high: ${scans.filter(s => s.worstLabel === 'high').length}</div>
<div class="badge medium">medium: ${scans.filter(s => s.worstLabel === 'medium').length}</div>
<div class="badge low">low: ${scans.filter(s => s.worstLabel === 'low').length}</div>
<div class="badge clean">clean: ${scans.filter(s => !s.count).length}</div>
</div>

<h2>Findings</h2>
<table>
<thead><tr><th>ATK</th><th>Severity</th><th>Title</th><th>Evidence</th></tr></thead>
<tbody>${rows.map(r => `<tr><td colspan="4" style="background:#161b22;font-weight:600">${r.name} <span class="badge ${r.worstLabel}">${r.count ? r.worstLabel : 'clean'}</span></td></tr>${r.findingRows}`).join('')}</tbody>
</table>

<p class="meta">npm-scan v0.2.1 | Apache-2.0 + Commons Clause | <a href="https://github.com/YOUR_GITHUB_USERNAME/npm-scan">GitHub</a></p>
</body>
</html>`;
}
