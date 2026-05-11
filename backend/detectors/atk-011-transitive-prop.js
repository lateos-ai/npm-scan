export async function scan(pkgJson, files = []) {
  const findings = [];
  const code = files.map(f => f.content).join('\n');

  const highPatterns = [
    {
      pattern: /(?:exec|execSync|spawn)\s*\([^)]*npm\s+(?:install|link)\s*\./i,
      label: 'programmatic self-propagation via npm install/link'
    },
    {
      pattern: /fs\.(?:writeFile|writeFileSync|copyFile|copyFileSync)\s*\([^)]*(?:node_modules\/(?!\.)[^/]+).*(?:index\.js|main\.js|package\.json)/i,
      label: 'direct file write to peer node_modules'
    },
    {
      pattern: /fs\.(?:writeFile|writeFileSync)\s*\([^)]*package\.json[^)]*["']scripts["']/i,
      label: 'package.json script injection in another package'
    },
    {
      pattern: /fs\.(?:writeFile|writeFileSync)\s*\([^)]*\.\.\/[^)]*package\.json/i,
      label: 'writes modified package.json to sibling package'
    },
    {
      pattern: /(?:exec|execSync|spawn)\s*\([^)]*(?:\.\.\/|process\.env\.INIT_CWD).*npm\s+install/i,
      label: 'cross-directory npm install propagation'
    },
  ];

  for (const { pattern, label } of highPatterns) {
    if (pattern.test(code)) {
      findings.push({
        id: 'ATK-011',
        severity: 'high',
        title: 'Transitive propagation (worm)',
        description: `Package attempts lateral worm-style spread: ${label}`,
        evidence: 'transitive propagation pattern detected'
      });
      break;
    }
  }

  if (findings.length === 0) {
    const mediumPatterns = [
      {
        pattern: /process\.env\.npm_package_name/,
        label: 'reads own package name from env (self-awareness indicator)'
      },
      {
        pattern: /fs\.symlink(?:Sync)?\s*\([^)]*node_modules/,
        label: 'creates symlinks in node_modules (worm spreading mechanism)'
      },
      {
        pattern: /fs\.(?:mkdir|mkdirSync)\s*\([^)]*\.\.\/[^)]*node_modules/,
        label: 'creates directories in parent node_modules'
      },
      {
        pattern: /__dirname.*\.\.\/[^/]+\/node_modules.*require\(/,
        label: 'dynamic parent-node_modules require for lateral spread'
      },
    ];

    for (const { pattern, label } of mediumPatterns) {
      if (pattern.test(code)) {
        findings.push({
          id: 'ATK-011',
          severity: 'medium',
          title: 'Transitive propagation (worm)',
          description: label,
          evidence: 'potential propagation indicator'
        });
        break;
      }
    }
  }

  return findings;
}
