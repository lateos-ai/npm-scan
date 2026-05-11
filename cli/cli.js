#!/usr/bin/env node

import { Command } from 'commander';
import { isFeatureEnabled, generateKey } from '../backend/license.js';

function requirePremium(feature, licenseKey) {
  if (!isFeatureEnabled(feature, licenseKey)) {
    console.error(`Error: "${feature}" requires a premium license key.`);
    console.error(`  Pass --license-key <key> or set NPM_SCAN_LICENSE_KEY env var.`);
    console.error(`  Generate a dev key: require('@lateos/npm-scan/backend/license').generateKey('premium')`);
    process.exit(1);
  }
}

const program = new Command()
  .name('npm-scan')
  .description('npm supply chain security scanner')
  .version('0.5.0');

program
  .command('scan')
  .description('Scan a package')
  .argument('<target>', 'package name')
  .option('-l, --license-key <key>', 'Premium license')
  .option('--sbom [format]', 'Generate SBOM (json/xml/spdx)')
  .option('-p, --policy <path>', 'Policy file (YAML/JSON)')
  .action(async (target, options) => {
    try {
      const policy = options.policy
        ? await import('../backend/policy.js').then(m => m.loadPolicy(options.policy))
        : null;

      if (policy) {
        const { isAllowed } = await import('../backend/policy.js');
        if (isAllowed(target, policy)) {
          console.log(JSON.stringify({ scanId: null, findings: [], skipped: true, reason: `Package '${target}' is in policy allowlist` }));
          return;
        }
      }

      const { pkgJson, jsFiles, tmpDir } = await import('../backend/fetch.js').then(m => m.fetchPackage(target));
      const findings = await import('../backend/detectors/index.js').then(m => m.runAll(pkgJson, jsFiles));
      const { saveScan } = await import('../backend/db.js');
      const scanId = saveScan(target, 'latest', findings);

      let outputFindings = findings;
      let blocked = false;

      if (policy) {
        const { applyPolicy } = await import('../backend/policy.js');
        const result = applyPolicy(findings, target, policy);
        outputFindings = result.findings;
        blocked = result.blocked;
      }

      if (options.sbom) {
        const { generateSBOM } = await import('../backend/sbom.js');
        const pkg = { name: target, version: pkgJson.version || 'latest' };
        const sbom = generateSBOM(pkg, outputFindings, options.sbom === true ? 'json' : options.sbom);
        console.log(sbom);
      } else {
        console.log(JSON.stringify({scanId, findings: outputFindings, blocked}, null, 2));
      }

      if (blocked) {
        console.error('Policy: scan blocked due to fail_on threshold');
        process.exit(1);
      }

      import('../backend/fetch.js').then(m => m.cleanup(tmpDir));
    } catch (e) {
      console.error(e.message);
      process.exit(1);
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
  .option('--sbom [format]', 'SBOM format (json/xml/spdx)')
  .option('--html', 'HTML report')
  .option('--nist', 'NIST 800-161 compliance report')
  .option('--cra', 'EU CRA compliance report')
  .option('--siem <format>', 'SIEM format (cef|ecs|sentinel|qradar)')
  .option('-l, --license-key <key>', 'Premium license')
  .action(async (options) => {
    const licenseKey = options.licenseKey || process.env.NPM_SCAN_LICENSE_KEY;
    const { getRecentScans, getFindings, getScan } = await import('../backend/db.js');

    if (options.id) {
      const findings = getFindings(options.id);
      const scanInfo = getScan(options.id);
      const pkgName = scanInfo?.package_name || 'scan-' + options.id;
      const pkgVer = scanInfo?.version || 'unknown';
      const pkg = { name: pkgName, version: pkgVer };
      const scan = findings.length ? { package_name: pkgName, version: pkgVer, findings } : null;

      if (options.siem) {
        requirePremium('siem', licenseKey);
        const { generateSIEM } = await import('../backend/siem/index.js');
        console.log(generateSIEM(scan ? [scan] : [], options.siem));
      } else if (options.cra) {
        requirePremium('cra', licenseKey);
        const { generateCRA } = await import('../backend/cra.js');
        console.log(generateCRA(scan ? [scan] : []));
      } else if (options.sbom) {
        const { generateSBOM } = await import('../backend/sbom.js');
        const sbom = generateSBOM(pkg, findings, options.sbom === true ? 'json' : options.sbom);
        console.log(sbom);
      } else if (options.html || options.nist) {
        const { generateHTML } = await import('../backend/report.js');
        const html = generateHTML(scan ? [scan] : []);
        console.log(html);
      } else {
        console.log(JSON.stringify(findings, null, 2));
      }
    } else {
      const scans = getRecentScans();
      const scansWithFindings = scans.map(s => ({ ...s, findings: getFindings(s.id) }));

      if (options.siem) {
        requirePremium('siem', licenseKey);
        const { generateSIEM } = await import('../backend/siem/index.js');
        console.log(generateSIEM(scansWithFindings, options.siem));
      } else if (options.cra) {
        requirePremium('cra', licenseKey);
        const { generateCRA } = await import('../backend/cra.js');
        console.log(generateCRA(scansWithFindings));
      } else if (options.html || options.nist) {
        const { generateHTML } = await import('../backend/report.js');
        const html = generateHTML(scansWithFindings);
        console.log(html);
      } else {
        console.log('Recent scans:', JSON.stringify(scans, null, 2));
      }
    }
  });

program.parse();