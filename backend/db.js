import initSqlJs from 'sql.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(process.cwd(), 'npm-scan.db');
const SCHEMA_PATH = path.join(__dirname, 'db', 'schema.sql');

let db = null;
let initPromise = null;

async function ensureInit() {
  if (db) return;
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const SQL = await initSqlJs();
    if (fs.existsSync(DB_PATH)) {
      db = new SQL.Database(fs.readFileSync(DB_PATH));
    } else {
      db = new SQL.Database();
    }
    if (fs.existsSync(SCHEMA_PATH)) {
      db.run(fs.readFileSync(SCHEMA_PATH, 'utf8'));
    }
  })();
  return initPromise;
}

function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

function queryOne(sql, params = []) {
  return queryAll(sql, params)[0] || null;
}

function lastId() {
  const r = db.exec("SELECT last_insert_rowid()");
  return Number(r[0].values[0][0]);
}

function persist() {
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

export async function saveScan(pkgName, version = 'latest', findings = []) {
  await ensureInit();
  db.run("INSERT INTO scans (package_name, version) VALUES (?, ?)", [pkgName, version]);
  const scanId = lastId();
  const stmt = db.prepare("INSERT INTO findings (scan_id, atk_id, severity, description, evidence) VALUES (?, ?, ?, ?, ?)");
  for (const f of findings) {
    stmt.run([scanId, f.id, f.severity, f.title || f.description, f.evidence || '']);
  }
  stmt.free();
  persist();
  return scanId;
}

export async function getRecentScans(limit = 10) {
  await ensureInit();
  return queryAll("SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", [limit]);
}

export async function getFindings(scanId) {
  await ensureInit();
  return queryAll("SELECT * FROM findings WHERE scan_id = ?", [scanId]);
}

export async function getScan(scanId) {
  await ensureInit();
  return queryOne("SELECT * FROM scans WHERE id = ?", [scanId]);
}

export async function close() {
  if (db) {
    persist();
    db.close();
    db = null;
    initPromise = null;
  }
}