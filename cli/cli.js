#!/usr/bin/env node

import { Command } from 'commander';

const program = new Command()
  .name('npm-scan')
  .description('npm supply chain security scanner')
  .version('0.2.5');

program
  .command('scan')
  .description('Scan a package')
  .argument('<target>', 'package name')
  .option('-l, --license-key <key>', 'Premium license')
  .option('--sbom [format]', 'Generate SBOM (json/xml/spdx)', 'json')
  .action(async (target, options) => {
    try {
      const { pkgJson, jsFiles, tmpDir } = await import('../backend/fetch.js').then(m => m.fetchPackage(target));
      const findings = await import('../backend/detectors/index.js').then(m => m.runAll(pkgJson, jsFiles));
      const { saveScan } = await import('../backend/db.js');
      const scanId = saveScan(target, 'latest', findings);

      if (options.sbom) {
        const { generateSBOM } = await import('../backend/sbom.js');
        const sbom = generateSBOM(pkgJson, findings, options.sbom === true ? 'json' : options.sbom);
        console.log(sbom);
      } else {
        console.log(JSON.stringify({scanId, findings}, null, 2));
      }

      import('../backend/fetch.js').then(m => m.cleanup(tmpDir));
    } catch (e) {
      console.error(e.message);
    }
  });

program
  .command('scan-lockfile')
  .description('Scan package-lock.json')
  .option('-f, --file <path>', 'lockfile path', 'package-lock.json')
  .action((options) => {
    console.log('Scanning lockfile:', options.file);
  });

program
  .command('report')
  .description('Generate report')
  .option('-i, --id <id>', 'Scan ID')
  .option('--sbom [format]', 'SBOM format (json/xml/spdx)', 'json')
  .option('--html', 'HTML report')
  .option('--nist', 'NIST 800-161 compliance report')
  .action(async (options) => {
    const { getRecentScans, getFindings, db } = await import('../backend/db.js');
    if (options.id) {
      const findings = getFindings(options.id);
      const pkg = { name: 'scanned-pkg', version: 'unknown' };
      if (options.sbom) {
        const { generateSBOM } = await import('../backend/sbom.js');
        const sbom = generateSBOM(pkg, findings, options.sbom === true ? 'json' : options.sbom);
        console.log(sbom);
      } else if (options.html || options.nist) {
        const { generateHTML } = await import('../backend/report.js');
        const scan = findings.length ? { package_name: 'scan-' + options.id, findings } : null;
        const html = generateHTML(scan ? [scan] : []);
        console.log(html);
      } else {
        console.log(JSON.stringify(findings, null, 2));
      }
    } else {
      if (options.html || options.nist) {
        const scans = getRecentScans();
        const scansWithFindings = scans.map(s => ({
          ...s,
          findings: getFindings(s.id)
        }));
        const { generateHTML } = await import('../backend/report.js');
        const html = generateHTML(scansWithFindings);
        console.log(html);
      } else {
        const scans = getRecentScans();
        console.log('Recent scans:', JSON.stringify(scans, null, 2));
      }
    }
  });

program.parse();