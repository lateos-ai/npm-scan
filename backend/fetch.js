import fetch from 'node-fetch';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { extract } from 'tar';
import zlib from 'zlib';
import { Readable } from 'stream';
import { pipeline } from 'stream/promises';

export async function fetchPackage(target) {
  const metaRes = await fetch(`https://registry.npmjs.org/${target}/latest`);
  const meta = await metaRes.json();

  if (!metaRes.ok || !meta.dist?.tarball) {
    throw new Error(`Package '${target}' not found on npm (${metaRes.status})`);
  }

  const tarUrl = meta.dist.tarball;
  const tarRes = await fetch(tarUrl);
  const buffer = Buffer.from(await tarRes.arrayBuffer());
  if (buffer.length > 500 * 1024 * 1024) throw new Error('Tarball too large');

  const tmpDir = path.join(os.tmpdir(), 'npm-scan-' + Date.now());
  fs.mkdirSync(tmpDir, { recursive: true });

  const stream = Readable.from(buffer);
  await pipeline(
    stream,
    zlib.createGunzip(),
    extract({ cwd: tmpDir, strip: 1 })
  );

  const pkgPath = path.join(tmpDir, 'package.json');
  const pkgJsonStr = fs.readFileSync(pkgPath, 'utf8');
  const pkgJson = JSON.parse(pkgJsonStr);

  const jsFiles = walkFiles(tmpDir, '.js').map(p => ({
    path: p,
    content: fs.readFileSync(p, 'utf8')
  }));

  return { pkgJson, jsFiles, tmpDir };
}

function walkFiles(dir, ext) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name !== 'node_modules') {
      results.push(...walkFiles(full, ext));
    } else if (entry.isFile() && full.endsWith(ext)) {
      results.push(full);
    }
  }
  return results;
}

export function cleanup(tmpDir) {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}