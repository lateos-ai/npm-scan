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
  .version('0.9.7');

program
  .command('scan')
  .description('Scan a package')
  .argument('[target]', 'package name')
  .option('-f, --file <path>', 'local tarball path')
  .option('-l, --license-key <key>', 'Premium license')
  .option('--sbom [format]', 'Generate SBOM (json/xml/spdx)')
  .option('-p, --policy <path>', 'Policy file (YAML/JSON)')
  .option('--fail-on <level>', 'Exit with code 1 if findings >= level (low|medium|high|critical)', 'none')
  .option('--sarif [file]', 'Output SARIF v2.1 format to file or stdout')
  .option('--csv [file]', 'Output CSV format to file or stdout')
  .option('--score-only', 'Output only the risk score (0-10)')
  .action(async (target, options) => {
    try {
      if (!target && !options.file) {
        console.error('Error: specify a package name or --file <path>');
        process.exit(1);
      }

      const policy = options.policy
        ? await import('../backend/policy.js').then(m => m.loadPolicy(options.policy))
        : null;

      if (policy) {
        const { isAllowed } = await import('../backend/policy.js');
        if (target && isAllowed(target, policy)) {
          console.log(JSON.stringify({ scanId: null, findings: [], skipped: true, reason: `Package '${target}' is in policy allowlist` }));
          return;
        }
      }

      const { pkgJson, jsFiles, tmpDir } = options.file
        ? await import('../backend/fetch.js').then(m => m.scanLocalTarball(options.file))
        : await import('../backend/fetch.js').then(m => m.fetchPackage(target));
      const pkgName = target || pkgJson.name || 'unknown';
      const findings = await import('../backend/detectors/index.js').then(m => m.runAll(pkgJson, jsFiles));
      const { saveScan } = await import('../backend/db.js');
      const scanId = await saveScan(pkgName, 'latest', findings);

      let outputFindings = findings;
      let blocked = false;

      if (policy) {
        const { applyPolicy } = await import('../backend/policy.js');
        const result = applyPolicy(findings, pkgName, policy);
        outputFindings = result.findings;
        blocked = result.blocked;
      }

      const { calculateRiskScore } = await import('../backend/report.js');
      const riskScore = calculateRiskScore(outputFindings);

      if (options.scoreOnly) {
        console.log(riskScore);
        import('../backend/fetch.js').then(m => m.cleanup(tmpDir));
        return;
      }

      if (options.sarif) {
        const { generateSARIF } = await import('../backend/report.js');
        const scan = { package_name: pkgName, version: pkgJson.version || 'latest', findings: outputFindings };
        const sarifOutput = generateSARIF(scan);
        if (options.sarif === true || !options.sarif) {
          console.log(sarifOutput);
        } else {
          const { writeFileSync } = await import('fs');
          writeFileSync(options.sarif, sarifOutput);
          console.log(`SARIF output written to ${options.sarif}`);
        }
      } else if (options.csv) {
        const { generateCSV } = await import('../backend/report.js');
        const scan = { package_name: pkgName, version: pkgJson.version || 'latest', findings: outputFindings };
        const csvOutput = generateCSV([scan]);
        if (options.csv === true || !options.csv) {
          console.log(csvOutput);
        } else {
          const { writeFileSync } = await import('fs');
          writeFileSync(options.csv, csvOutput);
          console.log(`CSV output written to ${options.csv}`);
        }
      } else if (options.sbom) {
        const { generateSBOM } = await import('../backend/sbom.js');
        const pkg = { name: pkgName, version: pkgJson.version || 'latest' };
        const sbom = generateSBOM(pkg, outputFindings, options.sbom === true ? 'json' : options.sbom);
        console.log(sbom);
      } else {
        console.log(JSON.stringify({scanId, findings: outputFindings, blocked, riskScore}, null, 2));
      }

      if (blocked) {
        console.error('Policy: scan blocked due to fail_on threshold');
        process.exit(1);
      }

      if (options.failOn !== 'none') {
        const severityLevels = { low: 1, medium: 2, high: 3, critical: 4 };
        const failLevel = severityLevels[options.failOn] || 0;
        const hasBlockingFindings = outputFindings.some(f => (severityLevels[f.severity] || 0) >= failLevel);
        if (hasBlockingFindings) {
          console.error(`Fail: findings with severity >= ${options.failOn} detected`);
          process.exit(1);
        }
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
  .option('--fail-on <level>', 'Exit with code 1 if findings >= level (low|medium|high|critical)', 'none')
  .option('--csv [file]', 'Output CSV format to file or stdout')
  .option('--sarif [file]', 'Output SARIF v2.1 format to file or stdout')
  .action((options) => {
    console.log('Scanning lockfile:', options.file);
  });

program
.command('report')
  .description('Generate report')
  .option('-i, --id <id>', 'Scan ID')
  .option('--sbom [format]', 'SBOM format (json/xml/spdx)')
  .option('--html', 'HTML report')
  .option('--text', 'Plain text report')
  .option('--csv [file]', 'CSV export to file or stdout')
  .option('--nist', 'NIST 800-161 compliance report')
  .option('--cra', 'EU CRA compliance report')
  .option('--siem <format>', 'SIEM format (cef|ecs|sentinel|qradar)')
  .option('--pdf', 'PDF report (premium)')
  .option('-o, --output <path>', 'Output file path')
  .option('-l, --license-key <key>', 'Premium license')
  .action(async (options) => {
    const licenseKey = options.licenseKey || process.env.NPM_SCAN_LICENSE_KEY;
    const { getRecentScans, getFindings, getScan } = await import('../backend/db.js');

    if (options.id) {
      const findings = await getFindings(options.id);
      const scanInfo = await getScan(options.id);
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
      } else if (options.pdf) {
        requirePremium('nist-pdf', licenseKey);
        const { generatePDF } = await import('../backend/pdf.js');
        const pdfBytes = await generatePDF(scan ? [scan] : []);
        const outPath = options.output || `${pkgName}-${options.id}-report.pdf`;
        await import('fs').then(m => m.writeFileSync(outPath, pdfBytes));
        console.log(`PDF report written to ${outPath}`);
      } else if (options.text) {
        const { generateText } = await import('../backend/report.js');
        console.log(generateText(scan ? [scan] : []));
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
      const scans = await getRecentScans();
      const scansWithFindings = await Promise.all(scans.map(async s => ({ ...s, findings: await getFindings(s.id) })));

      if (options.siem) {
        requirePremium('siem', licenseKey);
        const { generateSIEM } = await import('../backend/siem/index.js');
        console.log(generateSIEM(scansWithFindings, options.siem));
      } else if (options.cra) {
        requirePremium('cra', licenseKey);
        const { generateCRA } = await import('../backend/cra.js');
        console.log(generateCRA(scansWithFindings));
      } else if (options.pdf) {
        requirePremium('nist-pdf', licenseKey);
        const { generatePDF } = await import('../backend/pdf.js');
        const pdfBytes = await generatePDF(scansWithFindings);
        const date = new Date().toISOString().slice(0, 10);
        const outPath = options.output || `npm-scan-report-${date}.pdf`;
        await import('fs').then(m => m.writeFileSync(outPath, pdfBytes));
        console.log(`PDF report written to ${outPath}`);
      } else if (options.text) {
        const { generateText } = await import('../backend/report.js');
        console.log(generateText(scansWithFindings));
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