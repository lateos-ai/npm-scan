export async function scan(pkgJson, files = []) {
  const findings = [];
  const repo = pkgJson.repository || {};
  const repoUrl = typeof repo === 'string' ? repo : (repo.url || '');
  const pkgName = (pkgJson.name || '').toLowerCase();

  const knownRepos = {
    lodash: 'lodash/lodash',
    chalk: 'chalk/chalk',
    react: 'facebook/react',
    axios: 'axios/axios',
    express: 'expressjs/express',
    vue: 'vuejs/core',
    typescript: 'microsoft/typescript',
    moment: 'moment/moment',
    uuid: 'uuidjs/uuid',
    commander: 'tj/commander.js',
    debug: 'debug-js/debug',
    semver: 'npm/node-semver',
    underscore: 'jashkenas/underscore',
    request: 'request/request',
    async: 'caolan/async',
    cheerio: 'cheeriojs/cheerio',
    bluebird: 'petkaantonov/bluebird',
    jest: 'jestjs/jest',
    mocha: 'mochajs/mocha',
    dotenv: 'motdotla/dotenv',
    glob: 'isaacs/node-glob',
  };

  if (repoUrl && repoUrl.includes('github.com')) {
    const repoMatch = repoUrl.match(/github\.com[\/:]([\w.-]+\/[\w.-]+?)(?:\.git)?$/);
    if (repoMatch) {
      const ghRepo = repoMatch[1].toLowerCase();
      const ghName = ghRepo.split('/')[1];
      const ghOrg = ghRepo.split('/')[0];
      const shortName = pkgName.split('/').pop();

      if (ghName !== shortName) {
        const expectedRepo = knownRepos[pkgName] || knownRepos[shortName];

        if (expectedRepo && expectedRepo !== ghRepo) {
          findings.push({
            id: 'ATK-008',
            severity: 'high',
            title: 'Tarball tampering suspect',
            description: `Repository "${ghRepo}" does not match expected "${expectedRepo}" for package "${pkgName}"`,
            evidence: `repo: ${ghRepo}, expected: ${expectedRepo}`
          });
        } else {
          const orgExpected = knownRepos[shortName];
          if (orgExpected) {
            const expectedOrg = orgExpected.split('/')[0];
            if (ghOrg !== expectedOrg) {
              findings.push({
                id: 'ATK-008',
                severity: 'medium',
                title: 'Tarball tampering suspect',
                description: `Repository "${ghRepo}" is a different repo under a different org (legitimate: ${expectedRepo})`,
                evidence: `org mismatch: ${ghOrg} vs ${expectedOrg}`
              });
            }
          }
        }
      }
    }
  }

  const code = files.map(f => f.content).join('\n');
  const embeddedIntros = code.match(/\/\/\s*Source:\s*(https?:\/\/[^\s]+)/gi);
  if (embeddedIntros && repoUrl) {
    for (const intro of embeddedIntros) {
      const srcUrl = intro.replace(/\/\/\s*Source:\s*/i, '').trim();
      try {
        if (!repoUrl.includes(new URL(srcUrl).hostname)) {
          findings.push({
            id: 'ATK-008',
            severity: 'medium',
            title: 'Tarball tampering suspect',
            description: 'Source URL in file does not match declared repository',
            evidence: srcUrl
          });
        }
      } catch {
        // ignore malformed URLs
      }
    }
  }

  return findings;
}
