export function generateCRA(scans) {
  const atkMap = {};
  for (const s of scans) {
    for (const f of (s.findings || [])) {
      const key = f.atk_id || f.id;
      if (!atkMap[key]) atkMap[key] = [];
      atkMap[key].push({ ...f, package_name: s.package_name, version: s.version });
    }
  }

  const CRA_ARTICLES = [
    { article: 'Art. 7', title: 'Secure by default configuration', atkId: 'ATK-001', desc: 'Lifecycle hooks used for insecure defaults' },
    { article: 'Art. 7', title: 'Secure by default configuration', atkId: 'ATK-010', desc: 'Anti-analysis in default state' },
    { article: 'Art. 10(1)', title: 'Vulnerability disclosure', atkId: 'ATK-008', desc: 'Tarball integrity prevents disclosure accuracy' },
    { article: 'Art. 10(2)', title: 'Known vulnerability reporting', atkId: 'ATK-006', desc: 'Dependency confusion undermines visibility' },
    { article: 'Art. 11', title: 'Software Bill of Materials', atkId: 'ATK-008', desc: 'Integrity of SBOM entries must be verified' },
    { article: 'Art. 11', title: 'Software Bill of Materials', atkId: 'ATK-006', desc: 'SBOM must reflect actual dependency graph' },
    { article: 'Annex I(1.1)', title: 'No known exploitable vulnerabilities', atkId: 'ATK-009', desc: 'Conditional triggers may activate known vulns' },
    { article: 'Annex I(1.3)', title: 'Least privilege', atkId: 'ATK-003', desc: 'Credential harvesting violates least privilege' },
    { article: 'Annex I(1.5)', title: 'Limited attack surface', atkId: 'ATK-002', desc: 'Obfuscation increases attack surface' },
    { article: 'Annex I(1.5)', title: 'Limited attack surface', atkId: 'ATK-004', desc: 'Persistence mechanisms expand attack surface' },
    { article: 'Annex I(1.5)', title: 'Limited attack surface', atkId: 'ATK-005', desc: 'Network exfiltration expands attack surface' },
    { article: 'Annex I(2.1)', title: 'Protection against unauthorized access', atkId: 'ATK-003', desc: 'Credential harvesting enables unauthorized access' },
    { article: 'Annex I(2.3)', title: 'Data integrity', atkId: 'ATK-008', desc: 'Tarball tampering violates data integrity' },
    { article: 'Annex I(2.3)', title: 'Data integrity', atkId: 'ATK-011', desc: 'Propagation attacks compromise data integrity' },
    { article: 'Annex I(3.2)', title: 'Incident detection and reporting', atkId: 'ATK-009', desc: 'Conditional triggers evade incident detection' },
    { article: 'Annex I(3.2)', title: 'Incident detection and reporting', atkId: 'ATK-010', desc: 'Sandbox evasion defeats incident detection' },
    { article: 'Annex I(3.3)', title: 'Supply chain security monitoring', atkId: 'ATK-011', desc: 'Propagation requires SC monitoring' },
    { article: 'Annex I(3.3)', title: 'Supply chain security monitoring', atkId: 'ATK-007', desc: 'Typosquatting undermines SC trust' },
  ];

  let rows = '';
  for (const { article, title, atkId, desc } of CRA_ARTICLES) {
    const findings = atkMap[atkId] || [];
    const status = findings.length > 0 ? 'fail' : 'pass';
    const colorClass = status === 'pass' ? 'pass' : 'fail';
    const label = findings.length > 0 ? `${findings.length} finding(s)` : 'No findings';
    rows += `<tr><td>${article}</td><td>${title}</td><td>${desc}</td><td class="nist-${colorClass}">${label}</td><td>${atkId}</td></tr>`;
  }

  return `<h2>EU CRA Compliance Summary</h2>
<table>
<thead><tr><th>CRA Article</th><th>Requirement</th><th>Relevance</th><th>Status</th><th>ATK</th></tr></thead>
<tbody>${rows}</tbody>
</table>`;
}

export function generateCRAHTML(scans) {
  const body = generateCRA(scans);
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>EU CRA Compliance Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }
h1, h2 { color: #58a6ff; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; }
th { background: #161b22; }
.nist-pass { background: #1b3a1b; color: #7ee787; }
.nist-fail { background: #3a1b1b; color: #ff7b72; }
.meta { color: #8b949e; font-size: 13px; margin-top: 30px; }
</style></head>
<body>
<h1>npm-scan EU CRA Compliance Report</h1>
<p>Generated ${new Date().toISOString()} | npm-scan v${process.env.npm_package_version || '0.4.0'}</p>
${body}
<p class="meta">EU Cyber Resilience Act (Regulation 2023/2841) mapped to ATK findings.</p>
</body></html>`;
}