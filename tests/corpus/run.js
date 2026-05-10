import { globSync } from 'glob';
import { readFileSync, mkdtempSync } from 'fs';
import { execSync } from 'child_process';
import { fetchPackage, cleanup } from '../../backend/fetch.js';
import { runAll } from '../../backend/detectors/index.js';
import os from 'os';
import path from 'path';

function scanLocalTarball(tarPath) {
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'npm-scan-corpus-'));
  execSync(`tar xzf "${tarPath}" -C "${tmpDir}"`, { stdio: 'pipe' });
  const pkgPath = globSync(path.join(tmpDir, '**', 'package.json'), { nodir: true })[0];
  if (!pkgPath) throw new Error(`No package.json in ${tarPath}`);
  const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf8'));
  const pkgDir = path.dirname(pkgPath);
  const jsFiles = globSync(path.join(pkgDir, '**', '*.js'), { nodir: true }).map(p => ({
    path: p,
    content: readFileSync(p, 'utf8')
  }));
  return { pkgJson, jsFiles, tmpDir };
}

let cleanFails = 0;
let malFails = 0;
let cleanTotal = 0;
let malTotal = 0;

console.log('--- Clean corpus (remote) ---');
for (const pkg of ['lodash', 'chalk', 'react', 'axios', 'express']) {
  cleanTotal++;
  try {
    const { pkgJson, jsFiles, tmpDir } = await fetchPackage(pkg);
    const findings = await runAll(pkgJson, jsFiles);
    const bad = findings.filter(f => f.severity === 'high' || f.severity === 'critical');
    const badIds = bad.map(f => f.id).join(', ');
    if (bad.length > 0) {
      console.log(`  FAIL ${pkg}: ${bad.length} high/crit (${badIds})`);
      cleanFails++;
    } else {
      console.log(`  OK   ${pkg} (no high/crit findings)`);
    }
    cleanup(tmpDir);
  } catch (e) {
    console.log(`  ERR  ${pkg}: ${e.message}`);
    cleanFails++;
  }
}

console.log('--- Malicious corpus (local) ---');
const malTars = globSync('tests/corpus/malicious/*.tgz');
malTotal = malTars.length;
for (const tar of malTars) {
  const name = path.basename(tar, '.tgz');
  try {
    const { pkgJson, jsFiles } = scanLocalTarball(tar);
    const findings = await runAll(pkgJson, jsFiles);
    const ids = findings.map(f => f.id).join(', ');
    if (findings.length === 0) {
      console.log(`  FAIL ${name}: no findings`);
      console.log(`    scripts: ${JSON.stringify(pkgJson.scripts || {})}`);
      console.log(`    deps: ${JSON.stringify(pkgJson.dependencies || {})}`);
      console.log(`    js files: ${jsFiles.length}`);
      malFails++;
    } else {
      console.log(`  OK   ${name}: ${ids}`);
    }
  } catch (e) {
    console.log(`  ERR  ${name}: ${e.message}`);
    malFails++;
  }
}

const fpRate = cleanTotal > 0 ? (cleanFails / cleanTotal * 100).toFixed(1) : 'N/A';
const malDetectRate = malTotal > 0 ? ((malTotal - malFails) / malTotal * 100).toFixed(1) : 'N/A';
console.log(`\n=== Corpus Results ===`);
console.log(`Clean packages: ${cleanTotal}, Malicious samples: ${malTotal}`);
console.log(`Clean FP rate: ${fpRate}% (${cleanFails}/${cleanTotal} high/crit)`);
console.log(`Mal detect rate: ${malDetectRate}% (${malTotal - malFails}/${malTotal})`);

let exitCode = 0;
if (fpRate !== 'N/A' && Number(fpRate) >= 2) {
  console.log(`FP <2% : FAIL (${fpRate}% exceeds 2%)`);
  exitCode = 1;
} else {
  console.log('FP <2% : PASS');
}
if (malDetectRate !== 'N/A' && Number(malDetectRate) < 100) {
  console.log(`Mal 100% : FAIL (${malDetectRate}%)`);
  exitCode = 1;
} else {
  console.log('Mal 100% : PASS');
}
process.exit(exitCode);