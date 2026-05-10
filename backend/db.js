import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const DB_PATH = 'npm-scan.db';

let db;

function init() {
  db = new Database(DB_PATH);
  const schemaPath = path.join(process.cwd(), 'backend', 'db', 'schema.sql');
  const schema = fs.readFileSync(schemaPath, 'utf8');
  db.exec(schema);
}

init();

export function saveScan(pkgName, version = 'latest', findings = []) {
  const scanStmt = db.prepare('INSERT INTO scans (package_name, version) VALUES (?, ?)');
  const scanId = scanStmt.run(pkgName, version).lastInsertRowid;
  const findStmt = db.prepare('INSERT INTO findings (scan_id, atk_id, severity, description, evidence) VALUES (?, ?, ?, ?, ?)');
  for (const f of findings) {
    findStmt.run(scanId, f.id, f.severity, f.title || f.description, f.evidence || '');
  }
  return scanId;
}

export function getRecentScans(limit = 10) {
  return db.prepare('SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?').all(limit);
}

export function getFindings(scanId) {
  return db.prepare('SELECT * FROM findings WHERE scan_id = ?').all(scanId);
}

export function getScan(scanId) {
  return db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
}

export function close() {
  db.close();
}