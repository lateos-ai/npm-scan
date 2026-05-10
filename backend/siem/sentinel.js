export function generateSentinel(scans) {
  const events = [];
  for (const s of scans) {
    for (const f of (s.findings || [])) {
      const atkId = f.atk_id || f.id;
      events.push({
        TimeGenerated: new Date().toISOString(),
        Computer: process.env.COMPUTERNAME || process.env.HOSTNAME || 'npm-scan-host',
        SourceSystem: 'npm-scan',
        DeviceVendor: 'Lateos',
        DeviceProduct: 'npm-scan',
        DeviceVersion: process.env.npm_package_version || '0.7.0',
        SeverityLevel: f.severity,
        Severity: f.severity.toUpperCase(),
        EventType: 'npm-supply-chain-threat',
        ATKId: atkId,
        FindingTitle: f.title || f.description || '',
        FindingDescription: f.description || f.title || '',
        Evidence: f.evidence || '',
        PackageName: s.package_name || 'unknown',
        PackageVersion: s.version || 'unknown',
        Mitigation: f.mitigation || '',
        ThreatClassification: 'npm-supply-chain',
      });
    }
  }
  return JSON.stringify(events, null, 2);
}