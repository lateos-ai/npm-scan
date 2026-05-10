export function generateSBOM(pkgJson, findings, format = 'json') {
  if (format === 'spdx') return generateSPDX(pkgJson, findings);
  return generateCycloneDX(pkgJson, findings);
}

function generateCycloneDX(pkgJson, findings) {
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
      },
      tools: [{ name: 'npm-scan', version: '0.3.2' }]
    },
    vulnerabilities: findings.map(f => {
      const atkId = f.atk_id || f.id;
      return {
      id: atkId,
      source: { name: 'npm-scan' },
      ratings: [{ severity: f.severity }],
      description: f.description || f.title || '',
      recommendation: f.mitigation || 'Review evidence'
      };
    })
  };
  return JSON.stringify(bom, null, 2);
}

function generateSPDX(pkgJson, findings) {
  const pkgName = pkgJson.name || 'unknown';
  const pkgVer = pkgJson.version || 'unknown';
  const spdx = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${pkgName}@${pkgVer} npm-scan SBOM`,
    documentNamespace: `https://npm-scan.io/spdx/${pkgName}-${pkgVer}`,
    creationInfo: {
      creators: ['Tool: npm-scan'],
      created: new Date().toISOString()
    },
    packages: [{
      SPDXID: 'SPDXRef-Package',
      name: pkgName,
      versionInfo: pkgVer,
      packageFileName: `pkg:npm/${pkgName}@${pkgVer}`,
      primaryPackagePurpose: 'LIBRARY',
      externalRefs: [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: `pkg:npm/${pkgName}@${pkgVer}`
      }]
    }],
    annotations: findings.map(f => ({
      annotationDate: new Date().toISOString(),
      annotationType: 'OTHER',
      annotator: 'Tool: npm-scan',
      comment: `[${f.atk_id || f.id}] ${f.severity.toUpperCase()}: ${f.description || f.title || ''}`
    }))
  };
  return JSON.stringify(spdx, null, 2);
}