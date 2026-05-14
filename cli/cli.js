#!/usr/bin/env node

import { Command } from 'commander';
import { watch } from 'fs';
import { statSync } from 'fs';
import { execSync } from 'child_process';
import { glob } from 'glob';
import { isFeatureEnabled, generateKey } from '../backend/license.js';

function requirePremium(feature, licenseKey) {
  if (!isFeatureEnabled(feature, licenseKey)) {
    console.error(`Error: "${feature}" requires a premium license key.`);
    console.error(`  Pass --license-key <key> or set NPM_SCAN_LICENSE_KEY env var.`);
    console.error(`  Contact leo@lateos.ai for a premium license.`);
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
  .option('--audit-log <file>', 'Append scan record to immutable audit log (JSONL format)')
  .option('--fips', 'Enable FIPS 140-2/3 crypto mode (requires FIPS-enabled Node.js)')
  .option('--cache-dir <path>', 'Cache directory for offline/air-gapped scans')
  .option('--cache-ttl <seconds>', 'Cache TTL in seconds (default: 604800 = 7 days)', '604800')
  .option('--cache-size <bytes>', 'Max cache size in bytes (default: 1GB)', '1000000000')
  .action(async (target, options) => {
    try {
      if (options.fips) {
        process.env.NODE_OPTIONS = (process.env.NODE_OPTIONS || '') + ' --enable-fips';
      }

      const fetchOptions = {
        cacheDir: options.cacheDir,
        cacheTTL: parseInt(options.cacheTtl || '604800'),
        cacheMaxSize: parseInt(options.cacheSize || '1000000000')
      };

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
        : await import('../backend/fetch.js').then(m => m.fetchPackage(target, fetchOptions));
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

      if (options.auditLog) {
        const { writeFileSync, appendFileSync } = await import('fs');
        const entry = {
          timestamp: new Date().toISOString(),
          command: `scan ${target || options.file}`,
          package: pkgName,
          version: pkgJson.version || 'latest',
          riskScore,
          findingsCount: outputFindings.length,
          exitCode: 0
        };
        appendFileSync(options.auditLog, JSON.stringify(entry) + '\n');
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
  .description('Scan package lockfile (npm/yarn/pnpm)')
  .option('-f, --file <path>', 'lockfile path', 'package-lock.json')
  .option('--fail-on <level>', 'Exit with code 1 if findings >= level (low|medium|high|critical)', 'none')
  .option('--csv [file]', 'Output CSV format to file or stdout')
  .option('--sarif [file]', 'Output SARIF v2.1 format to file or stdout')
  .option('--watch', 'Watch for changes and re-scan automatically')
  .option('--debounce <ms>', 'Debounce delay in ms before rescanning (default: 1000)', '1000')
  .option('--silent', 'Suppress stdout output (useful for piping)')
  .option('--monorepo', 'Scan all lockfiles in workspace (auto-detect type)')
  .option('--yarn', 'Force yarn.lock format')
  .option('--pnpm', 'Force pnpm-lock.yaml format')
  .action(async (options) => {
    const silent = options.silent;
    const debounce = parseInt(options.debounce, 10) || 1000;
    const isWatch = options.watch;
    const isMonorepo = options.monorepo;

      if (isWatch) {
        if (isMonorepo) {
          const lockfiles = await glob('**/{package-lock.json,yarn.lock,pnpm-lock.yaml}', { ignore: 'node_modules/**' });

          if (!silent) {
            console.log(`\x1b[32m✔\x1b[0m npm-scan watch mode (monorepo) — ${lockfiles.length} lockfiles`);
            console.log(`  Debounce: ${debounce}ms | Press Ctrl+C to stop\n`);
          }

          let timers = {};
          for (const lf of lockfiles) {
            if (!silent) console.log(`  Watching: ${lf}`);
            const watcher = watch(lf, (eventType) => {
              if (eventType !== 'change') return;
              clearTimeout(timers[lf]);
              timers[lf] = setTimeout(() => {
                if (!silent) {
                  console.log(`\n\x1b[90m[${new Date().toLocaleTimeString()}]\x1b[0m ${lf} changed — scanning...`);
                }
                const lockType = lf.includes('yarn') ? '--yarn' : lf.includes('pnpm') ? '--pnpm' : '';
                try {
                  execSync(`node cli/cli.js scan-lockfile -f "${lf}" --fail-on ${options.failOn || 'high'} --silent ${lockType}`, { stdio: silent ? 'ignore' : 'inherit' });
                } catch (e) {}
              }, debounce);
            });
          }

          process.on('SIGINT', () => {
            if (!silent) console.log('\n\x1b[33m✖\x1b[0m Stopped.');
            process.exit(0);
          });
      } else {
        const lockfile = options.file;
        let lastSize = 0;
        try { lastSize = statSync(lockfile).size; } catch {}

        if (!silent) {
          console.log(`\x1b[32m✔\x1b[0m npm-scan watch mode — ${lockfile}`);
          console.log(`  Debounce: ${debounce}ms | Press Ctrl+C to stop\n`);
        }

        const watcher = watch(lockfile, (eventType) => {
          if (eventType !== 'change') return;
          const size = statSync(lockfile).size;
          if (size === lastSize) return;
          lastSize = size;
          if (!silent) console.log(`\n\x1b[90m[${new Date().toLocaleTimeString()}]\x1b[0m ${lockfile} changed — rescanning...`);
          try {
            execSync(`node cli/cli.js scan-lockfile --fail-on ${options.failOn || 'high'} --silent`, { stdio: silent ? 'ignore' : 'inherit' });
          } catch (e) {}
        });

        process.on('SIGINT', () => {
          watcher.close();
          if (!silent) console.log('\n\x1b[33m✖\x1b[0m Stopped.');
          process.exit(0);
        });
      }
    } else {
      const lockfile = options.file;
      try {
        const { parseLockfile, generateLockfileReport } = await import('../backend/lockfile.js');

        if (!silent) console.log(`\x1b[32m✔\x1b[0m Scanning lockfile: ${lockfile}`);

        const lockfileData = parseLockfile(lockfile, { autoDetect: !options.yarn && !options.pnpm });
        const results = generateLockfileReport(lockfileData);

        if (!silent) {
          console.log(`  Total deps: ${results.totalDependencies}`);
          console.log(`  Lockfile version: ${results.lockfileVersion}`);
          if (results.findings.length > 0) {
            console.log(`\n\x1b[31m🔴\x1b[0m ${results.findings.length} finding(s) found:\n`);
            for (const f of results.findings) {
              const color = f.severity === 'critical' ? '\x1b[31m' : f.severity === 'high' ? '\x1b[91m' : f.severity === 'medium' ? '\x1b[33m' : '\x1b[32m';
              console.log(`  ${color}${f.severity.toUpperCase().padEnd(8)}\x1b[0m ${f.id}: ${f.title}`);
              console.log(`           ${f.description}`);
            }
          } else {
            console.log(`\n\x1b[32m✔\x1b[0m No threats found.`);
          }
          console.log(`\n\x1b[36mRisk Score: ${results.riskScore}/10\x1b[0m`);
        }

        console.log(JSON.stringify(results, null, 2));

        if (results.findings.length > 0) {
          const failOn = options.failOn || 'none';
          if (failOn !== 'none') {
            const weights = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
            const maxWeight = Math.max(...results.findings.map(f => weights[f.severity] || 0));
            const failThreshold = weights[failOn] || 0;
            if (maxWeight >= failThreshold) process.exit(1);
          }
        }
      } catch (e) {
        console.error(`Error: ${e.message}`);
        process.exit(1);
      }
    }
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
  .option('--stig', 'STIG compliance report (DISA SRG-APP)')
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
      } else if (options.stig) {
        const { generateSTIG } = await import('../backend/report.js');
        const stig = generateSTIG(scan ? [scan] : []);
        console.log(stig);
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
      } else if (options.stig) {
        const { generateSTIG } = await import('../backend/report.js');
        const stig = generateSTIG(scansWithFindings);
        console.log(stig);
      } else {
        console.log('Recent scans:', JSON.stringify(scans, null, 2));
      }
    }
  });

program
  .command('serve')
  .description('Start API server (premium feature)')
  .option('-p, --port <port>', 'Port', '8000')
  .option('-h, --host <host>', 'Host', '0.0.0.0')
  .action(async (options) => {
    const licenseKey = process.env.NPM_SCAN_LICENSE_KEY || options.licenseKey;
    requirePremium('rest-api', licenseKey);

    const { createServer } = await import('http');
    const server = createServer(async (req, res) => {
      const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };

      if (req.url === '/health') {
        res.writeHead(200, headers);
        res.end(JSON.stringify({ status: 'ok', version: program.version() }));
        return;
      }

      if (req.url === '/scan' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
          try {
            const { package: pkg, options: scanOpts } = JSON.parse(body);
            const { scan } = await import('../backend/fetch.js');
            const results = await scan(pkg, { ...scanOpts, licenseKey });
            res.writeHead(200, headers);
            res.end(JSON.stringify({ results }));
          } catch (e) {
            res.writeHead(500, headers);
            res.end(JSON.stringify({ error: e.message }));
          }
        });
        return;
      }

      if (req.url.startsWith('/siem') && options.siemEnabled) {
        requirePremium('siem', licenseKey);
        res.writeHead(200, headers);
        res.end(JSON.stringify({ siem: 'enabled', endpoint: process.env.SIEM_ENDPOINT }));
        return;
      }

      if (req.url.startsWith('/pdf') && options.pdfEnabled) {
        requirePremium('nist-pdf', licenseKey);
        res.writeHead(200, headers);
        res.end(JSON.stringify({ pdf: 'enabled' }));
        return;
      }

      res.writeHead(404, headers);
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    server.listen(options.port, options.host, () => {
      console.log(`npm-scan API server running on http://${options.host}:${options.port}`);
    });
  });

program.parse();