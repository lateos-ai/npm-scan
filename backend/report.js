export function generateHTML(scans) {
  const rows = scans.map(s => {
    const findings = s.findings || [];
    const sevMap = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const worst = findings.reduce((m, f) => Math.max(m, sevMap[f.severity] || 0), 0);
    const worstLabel = ['', 'info', 'low', 'medium', 'high', 'critical'][worst] || 'clean';
    const color = { critical: '#d73a49', high: '#cb2431', medium: '#f66a0a', low: '#dbab09', clean: '#28a745' }[worstLabel] || '#28a745';
    const findingRows = findings.map(f =>
      `<tr><td>${f.atk_id || f.id}</td><td style="color:${color}">${f.severity}</td><td>${f.description || f.title || ''}</td><td>${(f.evidence || '').slice(0, 80)}</td></tr>`
    ).join('');
    return { name: s.package_name, worstLabel, color, count: findings.length, findingRows };
  });

  const criticalCount = scans.filter(s => s.findings?.some(f => f.severity === 'critical')).length;
  const highCount = scans.filter(s => s.findings?.some(f => f.severity === 'high')).length;
  const mediumCount = scans.filter(s => s.findings?.some(f => f.severity === 'medium')).length;
  const lowCount = scans.filter(s => s.findings?.some(f => f.severity === 'low')).length;
  const cleanCount = scans.filter(s => !s.findings?.length).length;

  const nistMap = generateNistTable(scans);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>npm-scan Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
h2 { color: #8b949e; margin-top: 28px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; }
th { background: #161b22; font-weight: 600; }
.summary { display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }
.badge { padding: 4px 12px; border-radius: 12px; font-size: 13px; font-weight: 600; }
.critical { background: #d73a49; color: #fff; }
.high { background: #cb2431; color: #fff; }
.medium { background: #f66a0a; color: #fff; }
.low { background: #dbab09; color: #000; }
.clean { background: #28a745; color: #fff; }
.meta { color: #8b949e; font-size: 13px; margin-top: 30px; }
.nist-pass { background: #1b3a1b; color: #7ee787; }
.nist-fail { background: #3a1b1b; color: #ff7b72; }
</style>
</head>
<body>
<h1>npm-scan Report</h1>
<p>Generated ${new Date().toISOString()}. ${scans.length} packages scanned.</p>

<div class="summary">
<div class="badge critical">critical: ${criticalCount}</div>
<div class="badge high">high: ${highCount}</div>
<div class="badge medium">medium: ${mediumCount}</div>
<div class="badge low">low: ${lowCount}</div>
<div class="badge clean">clean: ${cleanCount}</div>
</div>

<h2>Findings</h2>
<table>
<thead><tr><th>ATK</th><th>Severity</th><th>Title</th><th>Evidence</th></tr></thead>
<tbody>${rows.map(r => `<tr><td colspan="4" style="background:#161b22;font-weight:600">${r.name} <span class="badge ${r.worstLabel}">${r.count ? r.worstLabel : 'clean'}</span></td></tr>${r.findingRows}`).join('')}</tbody>
</table>

<h2>NIST SP 800-161 Compliance Summary</h2>
${nistMap}

<p class="meta">npm-scan v${process.env.npm_package_version || '0.3.2'} | Apache-2.0 + Commons Clause | NIST SP 800-161 mapped</p>
</body>
</html>`;
}

function getAtkFindings(scans) {
  const map = {};
  for (const s of scans) {
    for (const f of (s.findings || [])) {
      const key = f.atk_id || f.id;
      if (!map[key]) map[key] = [];
      map[key].push(f);
    }
  }
  return map;
}

const NIST_SR_MAP = {
  'ATK-001': { control: 'SR-3.1', title: 'Malicious code detection' },
  'ATK-002': { control: 'SR-4.2', title: 'Code obfuscation analysis' },
  'ATK-003': { control: 'SR-5.3', title: 'Credential protection' },
  'ATK-004': { control: 'SR-6.4', title: 'Persistence monitoring' },
  'ATK-005': { control: 'SR-7.5', title: 'Data exfiltration prevention' },
  'ATK-006': { control: 'SR-2.2', title: 'Dependency validation' },
  'ATK-007': { control: 'SR-2.1', title: 'Typosquatting prevention' },
  'ATK-008': { control: 'SR-8.1', title: 'Integrity verification' },
  'ATK-009': { control: 'SR-9.2', title: 'Conditional behavior analysis' },
  'ATK-010': { control: 'SR-10.3', title: 'Anti-evasion detection' },
  'ATK-011': { control: 'SR-11.4', title: 'Supply chain propagation monitoring' },
};

function generateNistTable(scans) {
  const atkMap = getAtkFindings(scans);
  let rows = '';
  for (const [atkId, { control, title }] of Object.entries(NIST_SR_MAP)) {
    const findings = atkMap[atkId] || [];
    const status = findings.length > 0 ? 'fail' : 'pass';
    const label = findings.length > 0 ? `${findings.length} findings` : 'No findings';
    const colorClass = status === 'pass' ? 'nist-pass' : 'nist-fail';
    rows += `<tr><td>${control}</td><td>${title}</td><td class="${colorClass}">${label}</td><td>${atkId}</td></tr>`;
  }
  return `<table>
<thead><tr><th>NIST Control</th><th>Control Title</th><th>Status</th><th>ATK ID</th></tr></thead>
<tbody>${rows}</tbody>
</table>`;
}