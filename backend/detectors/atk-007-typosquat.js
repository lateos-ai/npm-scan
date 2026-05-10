const TOP_PKGS = ['lodash', 'react', 'express', 'axios', 'chalk', 'vue', 'typescript', 'moment', 'uuid', 'commander', 'debug', 'semver', 'underscore', 'request', 'async', 'cheerio', 'bluebird', 'jest', 'mocha', 'dotenv', 'glob', 'minimist', 'body-parser', 'cors', 'helmet', 'jsonwebtoken', 'socket.io', 'redis', 'mongoose', 'sequelize', 'pg', 'passport', 'nodemailer', 'multer', 'bcrypt', 'winston', 'luxon', 'dayjs', 'rxjs', 'redux'];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const d = Array.from({ length: m + 1 }, (_, i) => [i]);
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      d[i][j] = Math.min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+(a[i-1]===b[j-1]?0:1));
  return d[m][n];
}

export async function scan(pkgJson) {
  const findings = [];
  const deps = { ...pkgJson.dependencies, ...pkgJson.devDependencies };
  const names = Object.keys(deps);
  if (names.length === 0) return findings;
  for (const d of names) {
    if (d.length < 4) continue;
    for (const top of TOP_PKGS) {
      const dist = levenshtein(d, top);
      if (dist > 0 && dist <= 2 && d !== top) {
        findings.push({
          id: 'ATK-007',
          severity: 'low',
          title: 'Typosquatting suspect',
          description: `"${d}" is edit-distance ${dist} from "${top}"`,
          evidence: d
        });
        break;
      }
    }
  }
  return findings;
}