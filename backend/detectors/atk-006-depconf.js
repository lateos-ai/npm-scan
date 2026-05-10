export async function scan(pkgJson) {
  const findings = [];
  const deps = { ...pkgJson.dependencies, ...pkgJson.devDependencies };
  const squat = Object.keys(deps).filter(d => /squat|confus|typo/i.test(d.toLowerCase()));
  if (squat.length) {
    findings.push({
      id: 'ATK-006',
      severity: 'medium',
      title: 'Dependency confusion',
      description: 'Suspicious dependency names',
      evidence: squat.join(', ')
    });
  }
  return findings;
}