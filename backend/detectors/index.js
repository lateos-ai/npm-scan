import * as atk001 from './atk-001-lifecycle.js';
import * as atk002 from './atk-002-obfusc.js';
import * as atk003 from './atk-003-creds.js';
import * as atk004 from './atk-004-persist.js';
import * as atk005 from './atk-005-exfil.js';
import * as atk006 from './atk-006-depconf.js';
import * as atk007 from './atk-007-typosquat.js';

export async function runAll(pkgJson, files = []) {
  const findings = [];
  findings.push(...await atk001.scan(pkgJson, files));
  findings.push(...await atk002.scan(pkgJson, files));
  findings.push(...await atk003.scan(pkgJson, files));
  findings.push(...await atk004.scan(pkgJson, files));
  findings.push(...await atk005.scan(pkgJson, files));
  findings.push(...await atk006.scan(pkgJson, files));
  findings.push(...await atk007.scan(pkgJson, files));
  return findings.sort((a, b) => b.severity.localeCompare(a.severity));
}