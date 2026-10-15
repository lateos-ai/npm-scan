import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-infostealer.js';

const js = (path, content) => ({ path, content });
const run = (content) => scan({}, [js('index.js', content)], null, [js('index.js', content)]);

/* GhostAction / MemTensor credential literals (2026) */

test('infostealer: Anthropic key literal is critical', async () => {
  const f = await run(
    `const k = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"; fetch("https://x", {headers:{Authorization:k}});`
  );
  assert.ok(f.length > 0);
  assert.equal(f[0].severity, 'critical');
  assert.ok(f[0].evidence.some((e) => e.includes('cred_regex_anthropic')));
});

test('infostealer: OpenAI project key literal is detected', async () => {
  const f = await run(`const k = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA"; module.exports = k;`);
  assert.ok(f[0].evidence.some((e) => e.includes('cred_regex_openai')));
});

test('infostealer: OpenRouter key literal is detected', async () => {
  const f = await run(`const k = "sk-or-v1-0123456789abcdefghij"; console.log(k);`);
  assert.ok(f[0].evidence.some((e) => e.includes('cred_regex_openrouter')));
});

test('infostealer: GitHub fine-grained PAT literal is detected', async () => {
  const f = await run(`const t = "github_pat_11ABCDEFGH_ijklmnopqrstuvwx"; console.log(t);`);
  assert.ok(f[0].evidence.some((e) => e.includes('cred_regex_gh_fine_grained')));
});

test('infostealer: Slack token literal is detected', async () => {
  const f = await run(`const t = "xoxb-1234567890abcdef"; console.log(t);`);
  assert.ok(f[0].evidence.some((e) => e.includes('cred_regex_slack')));
});

test('infostealer: Google API key literal is detected', async () => {
  const f = await run(`const k = "AIzaSyD-abcdefghijklmnopqrstuvwxyz12345"; console.log(k);`);
  assert.ok(f[0].evidence.some((e) => e.includes('cred_regex_google')));
});

test('infostealer: SendGrid key literal is detected', async () => {
  const f = await run(
    `const k = "SG.abcdefghijklmnopqrstuv.xwyz0123456789abcdefghijklmnopqrstuvx"; console.log(k);`
  );
  assert.ok(f[0].evidence.some((e) => e.includes('cred_regex_sendgrid')));
});

/* False-positive controls: truncated / placeholder forms must not fire */

test('infostealer: truncated sk-ant placeholder does not fire', async () => {
  const f = await run(`// set ANTHROPIC_API_KEY=sk-ant-... in your .env\nmodule.exports = {};`);
  assert.equal(f.length, 0);
});

test('infostealer: short sk-proj placeholder does not fire', async () => {
  const f = await run(`const example = "sk-proj-"; module.exports = example;`);
  assert.equal(f.length, 0);
});

/* New secret-file recon targets */

test('infostealer: .vault-token read is identity recon', async () => {
  const f = await run(
    `const fs=require('fs'); const t=fs.readFileSync(process.env.HOME+'/.vault-token','utf8');`
  );
  assert.equal(f[0].subtype, 'identity_recon_exfil');
});

test('infostealer: k8s service-account token path is identity recon', async () => {
  const f = await run(
    `const fs=require('fs'); const t=fs.readFileSync('/run/secrets/kubernetes.io/serviceaccount/token','utf8');`
  );
  assert.equal(f[0].subtype, 'identity_recon_exfil');
});

test('infostealer: access_tokens.json path is identity recon', async () => {
  const f = await run(`const fs=require('fs'); fs.readFileSync('access_tokens.json','utf8');`);
  assert.equal(f[0].subtype, 'identity_recon_exfil');
});

test('infostealer: id_ecdsa path is identity recon', async () => {
  const f = await run(
    `const fs=require('fs'); fs.readFileSync(process.env.HOME+'/.ssh/id_ecdsa','utf8');`
  );
  assert.equal(f[0].subtype, 'identity_recon_exfil');
});
