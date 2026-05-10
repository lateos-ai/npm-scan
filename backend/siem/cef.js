export function generateCEF(scans) {
  const entries = [];
  for (const s of scans) {
    for (const f of (s.findings || [])) {
      const atkId = f.atk_id || f.id;
      const desc = (f.description || f.title || '').replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
      const sevMap = { critical: 10, high: 8, medium: 5, low: 2 };
      const sev = sevMap[f.severity] || 5;
      const pkgName = (s.package_name || 'unknown').replace(/\|/g, '\\|');
      const pkgVer = (s.version || '').replace(/\|/g, '\\|');
      entries.push([
        'CEF:0',
        'npm-scan',
        'npm-scan',
        process.env.npm_package_version || '0.4.0',
        atkId,
        desc,
        String(sev),
        `suser=${pkgName} ${pkgVer}`,
        `msg=${desc}`,
        `cs1=${atkId}`,
        `cs1Label=atkId`,
        `cs2=${f.severity}`,
        `cs2Label=severity`,
        `cs3=${pkgName}`,
        `cs3Label=package`,
        `cs4=${pkgVer}`,
        `cs4Label=version`,
      ].join('|'));
    }
  }
  return entries.join('\n');
}