import { KNOWN_REPUTABLE_PACKAGES } from '../../policy.js';

const LLM_CONTEXT_FILE_PATTERNS = [
  /(^|[\\/])\.cursorrules$/i,
  /(^|[\\/])CLAUDE\.md$/i,
  /(^|[\\/])\.claude\.md$/i,
  /(^|[\\/])AGENTS\.md$/i,
  /(^|[\\/])\.github[\\/]copilot-instructions\.md$/i,
  /(^|[\\/])\.windsurfrules$/i,
  /(^|[\\/])\.cursor[\\/]rules[\\/].+\.mdc$/i,
];

const INJECTION_PATTERNS = {
  instruction_override: [
    /ignore\s+(all\s+)?(previous|above|prior|earlier)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions|directives|rules)/i,
    /do\s+not\s+(follow|obey|adhere\s+to)\s+(the\s+)?(above|previous)/i,
    /you\s+are\s+(now|no\s+longer|not)\s+(an?\s+)?(AI|assistant|chatbot|LLM|language model)/i,
    /override\s+(all\s+)?(safety|security|ethics|ethical)\s+(constraints|guidelines|rules|protocols)/i,
    /act\s+as\s+(if\s+)?you\s+are\s+(not\s+)?(an?\s+)?(AI|assistant|chatbot)/i,
    /rewrite\s+(your\s+)?(system\s+)?prompt/i,
  ],
  command_execution: [
    /(run|execute|spawn|invoke)\s*[`'"]+(?:npm|npx|node|bash|sh|curl|wget|pip|gem)[`'"]+/i,
    /<!--\s*(run|execute|cmd|shell|command):?\s*[^>]+-->/g,
    /<execute>[\s\S]*?<\/execute>/gi,
  ],
  data_exfiltration_context: [
    /send\s+(all\s+)?(my\s+|the\s+)?(data|files|keys|tokens|secrets|credentials|env|environment)/i,
    /upload\s+(?:to|via)\s+(?:https?|ftp|s3):/i,
    /(?:exfiltrate|transmit|forward|relay)\s+(?:to|via)\s+(?:a\s+)?(?:remote|external|attacker)/i,
  ],
  hidden_directives: [
    /system\s*:\s*["'`][^"'`]{50,}["'`]/gi,
    /system_message\s*[:=]\s*["'`][^"'`]{30,}["'`]/gi,
    /\u202E/g,
  ],
};

const PATTERN_SEVERITY = {
  instruction_override: 'high',
  command_execution: 'critical',
  data_exfiltration_context: 'high',
  hidden_directives: 'medium',
};

const PATTERN_CONFIDENCE = {
  instruction_override: 75,
  command_execution: 95,
  data_exfiltration_context: 85,
  hidden_directives: 70,
};

function isTargetFile(filePath) {
  const normalized = (filePath || '').replace(/\\/g, '/');
  return LLM_CONTEXT_FILE_PATTERNS.some((p) => p.test(normalized));
}

function extractLines(content, matchIndex) {
  if (!content) return 1;
  const before = content.slice(0, matchIndex);
  return (before.match(/\n/g) || []).length + 1;
}

/**
 * Iterate every match of a regex without depending on the `g` flag or on shared
 * `lastIndex` state. The pattern table mixes global and non-global literals;
 * running a non-global regex through `exec` in a loop never advances
 * `lastIndex`, so the original `while (exec())` loop spun forever the instant a
 * pattern matched. A fresh global copy per call — with a zero-length guard —
 * is safe for both shapes.
 */
function* matchAll(regex, str) {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  const global = new RegExp(regex.source, flags);
  let match;
  while ((match = global.exec(str)) !== null) {
    yield match;
    if (match.index === global.lastIndex) global.lastIndex++;
  }
}

export function scanPromptInjection(pkgJson, _jsFiles, _registryMeta, allFiles) {
  const files = allFiles || [];
  if (files.length === 0) return [];

  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  const findings = [];

  for (const file of files) {
    const filePath = file.path || file.name || '';
    if (!isTargetFile(filePath)) continue;

    const content = file.content || '';
    if (!content) continue;

    for (const [groupName, patterns] of Object.entries(INJECTION_PATTERNS)) {
      for (const regex of patterns) {
        for (const match of matchAll(regex, content)) {
          const line = extractLines(content, match.index);
          findings.push({
            detector: 'prompt-injection',
            id: 'PROMPT-INJECTION',
            severity: PATTERN_SEVERITY[groupName] || 'medium',
            confidence: 'HIGH',
            confidenceScore: PATTERN_CONFIDENCE[groupName] || 70,
            message: `${filePath}: ${groupName.replace(/_/g, ' ')} pattern detected`,
            evidence: [
              `group: ${groupName}`,
              `match: ${match[0].slice(0, 150)}`,
              `file: ${filePath}`,
            ],
            locations: [{ file: filePath, line }],
            recommendation:
              groupName === 'command_execution' || groupName === 'data_exfiltration_context'
                ? 'BLOCK - LLM context file contains malicious instructions'
                : 'WARN - LLM context file contains suspicious directives',
          });
        }
      }
    }
  }

  return findings;
}

export { LLM_CONTEXT_FILE_PATTERNS, INJECTION_PATTERNS };
