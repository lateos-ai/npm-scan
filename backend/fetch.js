import fs from 'fs';
import os from 'os';
import path from 'path';
import { extract } from 'tar';
import zlib from 'zlib';
import { Readable } from 'stream';
import { pipeline } from 'stream/promises';

export async function fetchPackage(target, options = {}) {
  const { cacheDir, cacheTTL = 604800, cacheMaxSize = 1000000000 } = options;
  const [name, version] = target.split('@').slice(1);
  const endpoint = version ? `/${name}/v/${version}` : `/${target}/latest`;

  if (cacheDir) {
    const cached = getFromCache(cacheDir, target, cacheTTL);
    if (cached) {
      const tmpDir = path.join(os.tmpdir(), 'npm-scan-cache-' + Date.now());
      return { ...(await extractTarball(cached, tmpDir)), meta: null };
    }
  }

  const metaRes = await fetch(`https://registry.npmjs.org${endpoint}`);
  const meta = await metaRes.json();

  if (!metaRes.ok || !meta.dist?.tarball) {
    throw new Error(`Package '${target}' not found on npm (${metaRes.status})`);
  }

  const tarUrl = meta.dist.tarball;
  const tarRes = await fetch(tarUrl);
  const buffer = Buffer.from(await tarRes.arrayBuffer());
  if (buffer.length > 500 * 1024 * 1024) throw new Error('Tarball too large');

  // Save to cache if enabled
  if (cacheDir) {
    saveToCache(cacheDir, target, buffer, cacheTTL, cacheMaxSize);
  }

  const tmpDir = path.join(os.tmpdir(), 'npm-scan-' + Date.now());
  return { ...(await extractTarball(buffer, tmpDir)), meta };
}

function getFromCache(cacheDir, target, ttl) {
  const cachePath = path.join(cacheDir, `${target.replace('/', '-')}.tgz`);
  const metaPath = path.join(cacheDir, `${target.replace('/', '-')}.meta.json`);
  
  try {
    if (!fs.existsSync(cachePath) || !fs.existsSync(metaPath)) return null;
    
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    const age = (Date.now() - meta.timestamp) / 1000;
    
    if (age > ttl) {
      fs.unlinkSync(cachePath);
      fs.unlinkSync(metaPath);
      return null;
    }
    
    return fs.readFileSync(cachePath);
  } catch {
    return null;
  }
}

function saveToCache(cacheDir, target, buffer, ttl, maxSize) {
  try {
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    
    // Prune if needed
    pruneCache(cacheDir, maxSize);
    
    const safeName = target.replace('/', '-');
    const cachePath = path.join(cacheDir, `${safeName}.tgz`);
    const metaPath = path.join(cacheDir, `${safeName}.meta.json`);
    
    fs.writeFileSync(cachePath, buffer);
    fs.writeFileSync(metaPath, JSON.stringify({ timestamp: Date.now(), size: buffer.length }));
  } catch (e) {
    // Cache write failure - continue without caching
  }
}

function pruneCache(cacheDir, maxSize) {
  try {
    const files = fs.readdirSync(cacheDir).filter(f => f.endsWith('.meta.json'));
    let totalSize = 0;
    const fileInfos = [];
    
    for (const f of files) {
      const meta = JSON.parse(fs.readFileSync(path.join(cacheDir, f), 'utf8'));
      const tarFile = f.replace('.meta.json', '.tgz');
      const size = meta.size || 0;
      totalSize += size;
      fileInfos.push({ tarFile, metaFile: f, timestamp: meta.timestamp, size });
    }
    
    if (totalSize > maxSize) {
      // Sort by oldest first and remove until under limit
      fileInfos.sort((a, b) => a.timestamp - b.timestamp);
      for (const info of fileInfos) {
        if (totalSize <= maxSize * 0.8) break; // Leave 20% margin
        try {
          fs.unlinkSync(path.join(cacheDir, info.tarFile));
          fs.unlinkSync(path.join(cacheDir, info.metaFile));
          totalSize -= info.size;
        } catch {}
      }
    }
  } catch {
    // Prune failure - ignore
  }
}

export async function scanLocalTarball(filePath) {
  const buffer = fs.readFileSync(filePath);
  const tmpDir = path.join(os.tmpdir(), 'npm-scan-local-' + Date.now());
  return await extractTarball(buffer, tmpDir);
}

async function extractTarball(buffer, tmpDir) {
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