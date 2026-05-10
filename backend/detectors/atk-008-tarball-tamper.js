export async function scan(pkgJson, files = []) {
  const findings = [];
  const repo = pkgJson.repository || {};
  const repoUrl = typeof repo === 'string' ? repo : (repo.url || '');
  const pkgName = (pkgJson.name || '').toLowerCase();

  const knownRepos = { lodash: 'lodash/lodash', chalk: 'chalk/chalk', react: 'facebook/react', axios: 'axios/axios', express: 'expressjs/express', vue: 'vuejs/vue', typescript: 'microsoft/typescript', moment: 'moment/moment', uuid: 'uuidjs/uuid', commander: 'tj/commander.js', debug: 'debug-js/debug', semver: 'npm/node-semver', underscore: 'jashkenas/underscore', request: 'request/request', async: 'caolan/async', cheerio: 'cheeriojs/cheerio', bluebird: 'petkaantonov/bluebird', jest: 'jestjs/jest', mocha: 'mochajs/mocha', dotenv: 'motdotla/dotenv', glob: 'isaacs/node-glob' };

  if (repoUrl && repoUrl.includes('github.com')) {
    const repoMatch = repoUrl.match(/github\.com[\/:]([\w.-]+\/[\w.-]+?)(?:\.git)?$/);
    if (repoMatch) {
      const ghRepo = repoMatch[1].toLowerCase();
      const ghName = ghRepo.split('/')[1];
      if (ghName !== pkgName && knownRepos[pkgName] && knownRepos[pkgName] !== ghRepo) {
        findings.push({
          id: 'ATK-008',
          severity: 'high',
          title: 'Tarball tampering suspect',
          description: `Repository "${ghRepo}" does not match expected "${knownRepos[pkgName]}" for package "${pkgName}"`,
          evidence: `repo: ${ghRepo}, expected: ${knownRepos[pkgName]}`
        });
      }
    }
  }

  const code = files.map(f => f.content).join('\n');
  const embeddedIntros = code.match(/\/\/\s*Source:\s*(https?:\/\/[^\s]+)/gi);
  if (embeddedIntros && repoUrl) {
    for (const intro of embeddedIntros) {
      const srcUrl = intro.replace(/\/\/\s*Source:\s*/i, '').trim();
      if (!repoUrl.includes(new URL(srcUrl).hostname)) {
        findings.push({
          id: 'ATK-008',
          severity: 'medium',
          title: 'Tarball tampering suspect',
          description: 'Source URL in file does not match declared repository',
          evidence: srcUrl
        });
      }
    }
  }

  return findings;
}