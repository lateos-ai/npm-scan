-- SQLite schema for local CLI mode (free tier)
-- Tables: scans, findings (ATK-linked)

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  package_name TEXT NOT NULL,
  version TEXT,
  scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  status TEXT DEFAULT 'completed',
  sbom_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  atk_id TEXT NOT NULL,
  severity TEXT CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  description TEXT,
  evidence TEXT,
  mitigation TEXT,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- View for reports
CREATE VIEW IF NOT EXISTS scan_findings AS
SELECT s.*, f.* FROM scans s
JOIN findings f ON s.id = f.scan_id;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scans_package ON scans(package_name);
CREATE INDEX IF NOT EXISTS idx_findings_atk ON findings(atk_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
