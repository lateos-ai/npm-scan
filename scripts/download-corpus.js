import fetch from 'node-fetch';
import { writeFileSync, existsSync } from 'fs';

const TOP_PKGS = [
  'lodash', 'chalk', 'react', 'axios', 'express',
  'tslib', 'commander', 'typescript', 'vue', 'next',
  'yargs', 'debug', 'moment', 'uuid', 'semver',
  'rimraf', 'eslint', 'prettier', 'webpack', 'babel-core',
  'underscore', 'request', 'async', 'cheerio', 'bluebird',
  'jest', 'mocha', 'dotenv', 'glob', 'node-fetch',
  'minimist', 'body-parser', 'cors', 'helmet', 'jsonwebtoken',
  'socket.io', 'redis', 'mongoose', 'sequelize', 'pg',
  'passport', 'nodemailer', 'multer', 'bcrypt', 'winston',
  'luxon', 'dayjs', 'class-validator', 'rxjs', 'redux'
];

for (const pkg of TOP_PKGS) {
  const file = `tests/corpus/clean/${pkg}.tgz`;
  if (existsSync(file)) { console.log(`SKIP ${pkg}`); continue; }
  try {
    const res = await fetch(`https://registry.npmjs.org/${pkg}/latest`);
    const meta = await res.json();
    const tarRes = await fetch(meta.dist.tarball);
    const buf = Buffer.from(await tarRes.arrayBuffer());
    writeFileSync(file, buf);
    console.log(`OK ${pkg} (${(buf.length/1024).toFixed(0)}KB)`);
  } catch (e) {
    console.log(`FAIL ${pkg}: ${e.message}`);
  }
}
