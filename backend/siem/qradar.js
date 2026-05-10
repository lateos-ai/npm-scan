export function generateQRadar(scans) {
  const events = [];
  for (const s of scans) {
    for (const f of (s.findings || [])) {
      const atkId = f.atk_id || f.id;
      events.push({
        source: 'npm-scan',
        version: process.env.npm_package_version || '0.7.0',
        devicetime: new Date().toISOString(),
        devicepayload: [
          s.package_name || 'unknown',
          s.version || 'unknown',
          atkId,
          f.severity,
          f.title || f.description || '',
          f.evidence || '',
        ].join('\t'),
        devicevendor: 'Lateos',
        devicename: 'npm-scan',
        deviceproduct: 'npm-scan',
        atk_id: atkId,
        severity: f.severity,
        package_name: s.package_name || 'unknown',
        package_version: s.version || 'unknown',
        finding_title: f.title || f.description || '',
        finding_description: f.description || f.title || '',
        evidence: f.evidence || '',
        mitigation: f.mitigation || '',
        raw_category: 'NPM Supply Chain Threat',
        qid: _qrQid(f.severity),
        category: _qrCategory(f.severity),
      });
    }
  }
  return events.map(e => JSON.stringify(e)).join('\n');
}

const QID_MAP = {
  critical: 90050001,
  high: 90050002,
  medium: 90050003,
  low: 90050004,
};

function _qrQid(severity) {
  return QID_MAP[severity] || 90050003;
}

function _qrCategory(severity) {
  const map = {
    critical: 'Critical Severity Malware',
    high: 'High Severity Malware',
    medium: 'Medium Severity Malware',
    low: 'Low Severity Malware',
  };
  return map[severity] || 'Medium Severity Malware';
}