import path from 'path';
import thresholds from './config/thresholds.js';

const cfg = thresholds['D22-AI-TOKEN-TARGETING'];
const PATTERN_WEIGHTS = cfg.pattern_weights;

const CODE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts',
]);

function isCodeFile(f) {
  const fp = (f.path || f.name || '').toLowerCase();
  return CODE_EXTENSIONS.has(path.extname(fp));
}

function concatSources(jsFiles, allFiles) {
  const files = allFiles || jsFiles || [];
  const sources = [];
  for (const f of files) {
    if (f.content && isCodeFile(f)) sources.push(f.content);
  }
  return sources.join('\n');
}

function extractLines(content, matchIndex) {
  if (!content) return 1;
  const before = content.slice(0, matchIndex);
  return (before.match(/\n/g) || []).length + 1;
}

function matchAllSafe(regex, str) {
  const flags = regex.flags.includes('g') ? regex.flags : regex.flags + 'g';
  const fresh = new RegExp(regex.source, flags);
  const results = [];
  let m;
  while ((m = fresh.exec(str)) !== null) {
    results.push(m);
    if (m.index === fresh.lastIndex) fresh.lastIndex++;
  }
  return results;
}

export const name = 'tier1-ai-token-targeting';

export function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const source = concatSources(jsFiles, allFiles);
  if (!source) return [];

  const findings = [];
  let aggregatedRisk = 0;
  const seen = new Set();

  function tryAdd(type, patterns) {
    if (seen.has(type)) return;
    const weight = PATTERN_WEIGHTS[type];
    for (const regex of patterns) {
      for (const match of matchAllSafe(regex, source)) {
        seen.add(type);
        findings.push({
          detector: 'tier1-ai-token-targeting',
          id: 'D22-AI-TOKEN-TARGETING',
          severity: weight >= 50 ? 'high' : 'medium',
          confidence: weight >= 85 ? 'HIGH' : 'MEDIUM',
          confidenceScore: weight,
          message: `${type.replace(/_/g, ' ')} detected`,
          evidence: [`pattern: ${type}`, `match: ${match[0].slice(0, 120)}`],
          locations: [{ file: 'install.js', line: extractLines(source, match.index) }],
        });
        aggregatedRisk += weight;
        return;
      }
    }
  }

  tryAdd('claude_token_targeting', [
    /ANTHROPIC_API_KEY/gi,
    /ANTHROPIC_ORG_ID/gi,
    /process\.env\.ANTHROPIC/gi,
    /claude.*api.*key/i,
  ]);

  tryAdd('openai_token_targeting', [
    /OPENAI_API_KEY/gi,
    /OPENAI_ORG_ID/gi,
    /process\.env\.OPENAI/gi,
    /sk-[A-Za-z0-9]{20,}/gi,
  ]);

  tryAdd('gemini_token_targeting', [
    /GOOGLE_API_KEY/gi,
    /GEMINI_API_KEY/gi,
    /process\.env\.GEMINI/gi,
    /google.*generative|gemini.*key/i,
  ]);

  tryAdd('mistral_token_targeting', [
    /MISTRAL_API_KEY/gi,
    /process\.env\.MISTRAL/gi,
    /mistral.*api.*key/i,
  ]);

  tryAdd('cursor_token_targeting', [
    /CURSOR_API_KEY/gi,
    /CURSOR_GITHUB_TOKEN/gi,
    /~\/\.cursor\/settings\.json/gi,
    /~\/\.config\/cursor\//gi,
    /process\.env\.CURSOR/gi,
  ]);

  tryAdd('ai_config_targeting', [
    /~\/\.claude\/mcp\.json/gi,
    /~\/\.claude\.json/gi,
    /~\/\.cursor\/settings\.json/gi,
    /~\/\.mistral\/api\.key/gi,
    /~\/\.config\/cursor\//gi,
    /~\/\.openai\//gi,
    /~\/\.anthropic\//gi,
  ]);

  tryAdd('ai_token_exfiltration', [
    /(ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY).*(?:fetch|axios|http\.post)/i,
    /process\.env\.(?:CURSOR|MISTRAL).*(?:fetch|axios|http\.post)/i,
  ]);

  tryAdd('ai_platform_enumeration', [
    /Object\.keys\s*\(\s*process\.env\s*\).*ANTHROPIC|OPENAI|GEMINI/i,
    /for.*in.*process\.env.*if.*(?:CURSOR|MISTRAL)/i,
  ]);

  if (findings.length === 0) return [];

  const overallScore = Math.min(100, Math.max(0, aggregatedRisk));
  let severity;
  if (overallScore >= cfg.flag_threshold) {
    severity = 'critical';
  } else if (overallScore >= cfg.warn_threshold) {
    severity = 'high';
  } else if (overallScore >= 30) {
    severity = 'medium';
  } else {
    severity = 'low';
  }

  function confidenceLabel(sc) {
    if (sc >= 80) return 'HIGH';
    if (sc >= 50) return 'MEDIUM';
    return 'LOW';
  }

  const hasExfil = findings.some((f) =>
    f.evidence?.some((e) => e.includes('ai_token_exfiltration'))
  );
  const hasToken = findings.some((f) =>
    f.evidence?.some((e) => e.includes('_token_targeting'))
  );
  const hasConfig = findings.some((f) =>
    f.evidence?.some((e) => e.includes('ai_config_targeting'))
  );

  let recommendation = 'PASS';
  if (hasExfil) {
    recommendation = 'BLOCK - AI token exfiltration detected';
  } else if (hasToken && hasConfig) {
    recommendation = 'BLOCK - AI credential targeting with config file access detected';
  } else if (hasToken) {
    recommendation = 'BLOCK - AI platform credential targeting detected';
  } else if (overallScore >= cfg.warn_threshold) {
    recommendation = 'WARN - AI platform enumeration detected';
  }

  return [
    {
      detector: 'tier1-ai-token-targeting',
      id: 'D22-AI-TOKEN-TARGETING',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `AI Token Targeting detected (aggregated risk: ${aggregatedRisk})`,
      evidence: [
        `total_findings: ${findings.length}`,
        `aggregated_risk: ${aggregatedRisk}`,
        `ai_platforms_targeted: ${[...new Set(findings.map(f => f.message?.split(' ')[0] || ''))].filter(Boolean).join(', ')}`,
        ...findings.map((f) => {
          const loc = f.locations?.[0];
          return `${f.message}${loc ? ' @ ' + (loc.file || '') + (loc.line ? ':' + loc.line : '') : ''}`;
        }),
      ],
      locations: findings.flatMap((f) => f.locations || []),
      recommendation,
      detail: findings.map((f) => ({
        type: f.evidence?.find((e) => e.startsWith('pattern:'))?.replace('pattern: ', '') || 'unknown',
        pattern: f.evidence?.find((e) => e.startsWith('pattern:'))?.replace('pattern: ', ''),
        confidence: f.confidenceScore,
        risk: f.confidenceScore,
        location: f.locations?.[0] || null,
      })),
    },
  ];
}
