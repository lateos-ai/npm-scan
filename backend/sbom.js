export function generateSBOM(pkgJson, findings, format = 'json') {
  // Stub CycloneDX without cyclonedx-node dependency
  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      component: {
        type: 'library',
        name: pkgJson.name || 'unknown',
        version: pkgJson.version || 'unknown',
        purl: `pkg:npm/${pkgJson.name || 'unknown'}@${pkgJson.version || 'unknown'}`
      }
    },
    vulnerabilities: findings.map(f => ({
      id: f.id,
      source: { name: 'npm-scan' },
      ratings: [{ severity: f.severity }],
      description: f.title || '',
      recommendation: f.mitigation || 'Review evidence'
    }))
  };
  return JSON.stringify(bom, null, 2);
}