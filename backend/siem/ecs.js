export function generateECS(scans) {
  const events = [];
  for (const s of scans) {
    for (const f of (s.findings || [])) {
      const atkId = f.atk_id || f.id;
      const sevMap = { critical: 100, high: 80, medium: 50, low: 20 };
      events.push({
        '@timestamp': new Date().toISOString(),
        event: {
          kind: 'alert',
          category: 'threat',
          type: ['indicator', 'threat'],
          action: 'npm-scan-detected',
          severity: sevMap[f.severity] || 50,
        },
        message: `[${atkId}] ${f.severity.toUpperCase()}: ${f.description || f.title || 'Unknown finding'}`,
        log: { level: f.severity },
        observer: {
          vendor: 'Lateos',
          product: 'npm-scan',
          version: process.env.npm_package_version || '0.7.0',
        },
        labels: {
          package: s.package_name || 'unknown',
          version: s.version || 'unknown',
          atk_id: atkId,
          severity: f.severity,
        },
        vulnerability: {
          classification: 'npm-supply-chain',
          reference: `https://npm-scan.io/atk/${atkId}`,
          id: atkId,
          description: f.description || f.title || null,
          enumeration: 'ATK',
        },
        file: f.evidence ? { name: f.evidence } : undefined,
      });
    }
  }
  return events.map(e => JSON.stringify(e)).join('\n');
}