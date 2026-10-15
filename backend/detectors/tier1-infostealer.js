import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import * as acorn from 'acorn';
import { extractPaasDomains, PAAS_CONFIDENCE_BOOST } from './lib/paas-domains.js';

const FS_READ_RE = /fs\.(?:readFile|readFileSync|readdir|readdirSync)\s*\(/g;
const HTTP_FETCH_RE = /\b(?:fetch|axios|got|superagent|request)\s*\(/g;
const CURL_WGET_RE = /\b(?:curl|wget|powershell)\s+/gi;
const CHILD_PROC_RE = /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/g;
const DOMAIN_EXTRACT_RE = /https?:\/\/([^'"\s)\];,\n\r]+)/gi;
const GITHUB_DOMAIN_RE = /github\.com/i;
const NPMJS_DOMAIN_RE = /npmjs\.(?:com|org)/i;

const AWS_KEY_RE = /AKIA[0-9A-Z]{16}/g;
const NPM_TOKEN_RE = /npm_[a-zA-Z0-9]{36}/g;
const GH_TOKEN_RE = /ghp_[a-zA-Z0-9]{30,40}/g;
const _GH_OLD_TOKEN_RE = /gho_[a-zA-Z0-9]{36}/g;
const _GITLAB_TOKEN_RE = /glpat-[a-zA-Z0-9_-]{20,}/g;
// GhostAction / MemTensor credential formats (2026). Presence-only triggers the
// same critical scaling as the AWS/GitHub/npm literals above; FP controls use
// truncated placeholders, which these length floors reject.
const GH_FINE_TOKEN_RE = /github_pat_[A-Za-z0-9_]{22,}/g;
const ANTHROPIC_KEY_RE = /sk-ant-[A-Za-z0-9_-]{20,}/g;
const OPENAI_PROJ_KEY_RE = /sk-proj-[A-Za-z0-9_-]{20,}/g;
const OPENROUTER_KEY_RE = /sk-or-(?:v1-)?[A-Za-z0-9_-]{20,}/g;
const SLACK_TOKEN_RE = /xox[baprs]-[A-Za-z0-9-]{10,}/g;
const GOOGLE_API_KEY_RE = /AIza[A-Za-z0-9_-]{35}/g;
const SENDGRID_KEY_RE = /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g;

// Ordered list consumed by extractCredentials; the existing AWS/npm/GitHub
// types are preserved so the cred-pattern → critical scaling is unchanged.
const CREDENTIAL_PATTERNS = [
  ['cred_regex_aws', AWS_KEY_RE],
  ['cred_regex_npm_token', NPM_TOKEN_RE],
  ['cred_regex_gh_token', GH_TOKEN_RE],
  ['cred_regex_gh_fine_grained', GH_FINE_TOKEN_RE],
  ['cred_regex_anthropic', ANTHROPIC_KEY_RE],
  ['cred_regex_openai', OPENAI_PROJ_KEY_RE],
  ['cred_regex_openrouter', OPENROUTER_KEY_RE],
  ['cred_regex_slack', SLACK_TOKEN_RE],
  ['cred_regex_google', GOOGLE_API_KEY_RE],
  ['cred_regex_sendgrid', SENDGRID_KEY_RE],
];

const ENV_DUMP_RE = /process\.env\.(?:AWS_[A-Z_]+|NPM_TOKEN|NPM_AUTH_TOKEN|GIT_TOKEN|SSH_KEY)/g;

const EVAL_RE = /\beval\s*\(/g;
const FUNCTION_CTOR_RE = /\bFunction\s*\(/g;
const _B64_STRING_RE = /['"`]([A-Za-z0-9+/]{40,}={0,2})['"`]/g;

const IDENTITY_PATH_RE =
  /(?:['"`](?:~\/\.gitconfig|~\/\.config\/git\/config|\.git\/config|\.git\/logs\/HEAD|~\/\.ssh\/[^'"`]*\.pub|~\/\.ssh\/id_ecdsa|~\/\.aws\/config|~\/\.config\/gcloud\/properties|~\/\.vault-token|\/etc\/resolv\.conf|\/run\/secrets\/|access_tokens\.json|stored_tokens)[`'"]|\.gitconfig|\.ssh\/|\.aws\/config|\.config\/git\/config|\.config\/gcloud\/properties|resolv\.conf|\.vault-token|access_tokens\.json|stored_tokens|id_ecdsa|\/run\/secrets\/)/g;
const GIT_CONFIG_EXEC_RE =
  /(?:(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"]git['"]\s*,\s*\[\s*['"]config['"]|(?:exec|execSync)\s*\(\s*['"]git\s+config\b)/g;

// Named malware signatures — zero-FP string literals for confirmed campaigns
const NAMED_SIGNATURES = [
  'Miasma: The Spreading Blight', // Miasma campaign, June 2026, @redhat-cloud-services compromise
];

function shannonEntropy(s) {
  const len = s.length;
  if (len === 0) {
    return 0;
  }
  const freq = {};
  for (const ch of s) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isMinified(content) {
  const identifiers = content.match(/\b[a-zA-Z_$][\w$]*\b/g);
  if (identifiers && identifiers.length > 0) {
    const avgLen = identifiers.reduce((s, id) => s + id.length, 0) / identifiers.length;
    if (avgLen < 3) {
      return true;
    }
  }
  return shannonEntropy(content) > 5.5;
}

function extractDomains(content) {
  const domains = [];
  let match;
  DOMAIN_EXTRACT_RE.lastIndex = 0;
  while ((match = DOMAIN_EXTRACT_RE.exec(content)) !== null) {
    domains.push(match[1]);
  }
  return domains;
}

function extractCredentials(content) {
  const creds = [];
  for (const [type, regex] of CREDENTIAL_PATTERNS) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(content)) !== null) {
      creds.push({ type, value: match[0], index: match.index });
    }
  }
  return creds;
}

function getLineColumn(content, index) {
  const lines = content.slice(0, index).split('\n');
  return { line: lines.length, column: lines[lines.length - 1].length + 1 };
}

function patternMatcher(f, content) {
  const file = f.path || f.name || 'unknown';
  const result = {
    file,
    hasPattern: false,
    patterns: [],
    locations: [],
    evidence: [],
    domainsFound: [],
    credsFound: [],
    isObfuscated: false,
  };

  if (!content) {
    return result;
  }

  result.isObfuscated =
    isMinified(content) || EVAL_RE.test(content) || FUNCTION_CTOR_RE.test(content);

  FS_READ_RE.lastIndex = 0;
  HTTP_FETCH_RE.lastIndex = 0;
  CHILD_PROC_RE.lastIndex = 0;
  CURL_WGET_RE.lastIndex = 0;

  const hasFsRead = FS_READ_RE.test(content);
  const hasHttpFetch = HTTP_FETCH_RE.test(content);
  const hasChildProc = CHILD_PROC_RE.test(content);
  const hasCurlWget = CURL_WGET_RE.test(content);

  const domains = extractDomains(content);
  const externalDomains = domains.filter((d) => !NPMJS_DOMAIN_RE.test(d));
  const gitHubDomains = domains.filter((d) => GITHUB_DOMAIN_RE.test(d) && !NPMJS_DOMAIN_RE.test(d));

  if (hasFsRead && hasHttpFetch) {
    const isGithubOnly =
      gitHubDomains.length > 0 && externalDomains.length === gitHubDomains.length;
    result.hasPattern = true;
    result.patterns.push({
      subtype: isGithubOnly ? 'nw_exfil_to_github' : 'fs_exfil',
      baseScore: 80,
    });
    result.domainsFound.push(...domains);
    FS_READ_RE.lastIndex = 0;
    const fsMatch = FS_READ_RE.exec(content);
    if (fsMatch) {
      const lc = getLineColumn(content, fsMatch.index);
      result.locations.push({ file, line: lc.line, column: lc.column });
    }
    result.evidence.push(
      isGithubOnly
        ? 'pattern: fs.readFile + network to GitHub'
        : 'pattern: fs.readFile + external fetch'
    );
  }

  if (hasFsRead && (hasChildProc || hasCurlWget)) {
    const isGithubOnly =
      gitHubDomains.length > 0 && externalDomains.length === gitHubDomains.length;
    result.hasPattern = true;
    result.patterns.push({
      subtype: isGithubOnly ? 'nw_exfil_to_github' : 'fs_exfil',
      baseScore: 80,
    });
    result.domainsFound.push(...domains);
    FS_READ_RE.lastIndex = 0;
    const fsMatch = FS_READ_RE.exec(content);
    if (fsMatch) {
      const lc = getLineColumn(content, fsMatch.index);
      result.locations.push({ file, line: lc.line, column: lc.column });
    }
    result.evidence.push(
      isGithubOnly
        ? 'pattern: fs.readFile + child_process to GitHub'
        : 'pattern: fs.readFile + child_process network'
    );
  }

  const creds = extractCredentials(content);
  if (creds.length > 0) {
    result.hasPattern = true;
    result.credsFound.push(...creds);
    const primaryType = creds[0].type;
    result.patterns.push({ subtype: primaryType, baseScore: 85 });
    const lc = getLineColumn(content, creds[0].index);
    result.locations.push({ file, line: lc.line, column: lc.column });
    const typeNames = [...new Set(creds.map((c) => c.type))];
    result.evidence.push(`hardcoded_credentials: ${creds.length} (${typeNames.join(', ')})`);
  }

  ENV_DUMP_RE.lastIndex = 0;
  const envMatch = ENV_DUMP_RE.exec(content);
  if (envMatch) {
    result.hasPattern = true;
    result.patterns.push({ subtype: 'env_dump', baseScore: 80 });
    const lc = getLineColumn(content, envMatch.index);
    result.locations.push({ file, line: lc.line, column: lc.column });
    result.evidence.push('pattern: process.env.AWS_* dump');
  }

  IDENTITY_PATH_RE.lastIndex = 0;
  GIT_CONFIG_EXEC_RE.lastIndex = 0;
  const identityMatch = IDENTITY_PATH_RE.exec(content);
  const gitConfigExec = GIT_CONFIG_EXEC_RE.exec(content);
  if (identityMatch || gitConfigExec) {
    result.hasPattern = true;
    const hitIndex = identityMatch ? identityMatch.index : gitConfigExec.index;
    result.patterns.push({ subtype: 'identity_recon_exfil', baseScore: 80 });
    const lc = getLineColumn(content, hitIndex);
    result.locations.push({ file, line: lc.line, column: lc.column });
    if (identityMatch) {
      result.evidence.push(`pattern: identity/credential-adjacent path read (${identityMatch[0]})`);
    }
    if (gitConfigExec) {
      result.evidence.push('pattern: git config exec for identity harvesting');
    }
  }

  const paasDomains = extractPaasDomains(content);
  if (paasDomains.length > 0) {
    result.domainsFound.push(...paasDomains.map((d) => `https://${d}`));
    result.evidence.push(`paas_domain: ${paasDomains[0]}`);
  }

  return result;
}

export const name = 'tier1-infostealer';

export async function scan(pkgJson, jsFiles, _registryMeta, _allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) {
    return [];
  }

  const files = jsFiles || [];

  // Named malware signature check — zero-FP string literals, early return
  const sigTexts = [];
  if (pkgJson?.scripts && typeof pkgJson.scripts === 'object') {
    for (const value of Object.values(pkgJson.scripts)) {
      if (typeof value === 'string') {
        sigTexts.push(value);
      }
    }
  }
  for (const f of files) {
    if (f?.content) {
      sigTexts.push(f.content);
    }
  }
  for (const sig of NAMED_SIGNATURES) {
    for (const text of sigTexts) {
      if (text.includes(sig)) {
        return [
          {
            detector: 'tier1-infostealer',
            id: 'TIER1-INFOSTEALER',
            severity: 'critical',
            confidence: 'CRITICAL',
            confidenceScore: 98,
            subtype: 'named_signature_miasma',
            message: `Named malware signature detected: "${sig}"`,
            evidence: [sig],
            locations: [{ file: '', line: 0 }],
            crossFiles: [],
            reference: 'Campaign 2 & 3',
          },
        ];
      }
    }
  }

  if (files.length === 0) {
    return [];
  }

  let parseFailCount = 0;

  for (const f of files) {
    const content = f.content || '';
    if (!content) {
      continue;
    }
    try {
      acorn.parse(content, { ecmaVersion: 'latest' });
    } catch {
      parseFailCount++;
    }
  }

  if (files.length >= 20 && parseFailCount / files.length >= 0.1) {
    return [];
  }

  const perFile = files.map((f) => patternMatcher(f, f.content || ''));
  const filesWithPatterns = perFile.filter((p) => p.hasPattern);

  if (filesWithPatterns.length === 0) {
    return [];
  }

  let highestBase = 0;
  let mainSubtype = '';
  let isObfuscated = false;
  const allEvidence = [];
  const allLocations = [];
  const involvedFiles = [];
  const _hasCreds = false;

  for (const f of filesWithPatterns) {
    if (!involvedFiles.includes(f.file)) {
      involvedFiles.push(f.file);
    }
    allLocations.push(...f.locations);
    allEvidence.push(...f.evidence);
    if (f.isObfuscated) {
      isObfuscated = true;
    }
    for (const p of f.patterns) {
      if (p.baseScore > highestBase) {
        highestBase = p.baseScore;
        mainSubtype = p.subtype;
      }
    }
  }

  let baseScore = highestBase;

  const anyCredPattern = filesWithPatterns.some((f) =>
    f.patterns.some((p) => p.subtype.startsWith('cred_'))
  );
  if (anyCredPattern) {
    baseScore = Math.min(100, Math.round(baseScore * 2.5));
  }

  if (isObfuscated) {
    baseScore += 15;
  }

  if (involvedFiles.length > 1) {
    baseScore = Math.min(100, Math.round(baseScore * 1.3));
  }

  const anyPaasDomain = filesWithPatterns.some((f) =>
    f.evidence.some((e) => e.startsWith('paas_domain:'))
  );
  if (anyPaasDomain) {
    baseScore = Math.min(100, baseScore + PAAS_CONFIDENCE_BOOST);
  }

  const anyIdentityRecon = filesWithPatterns.some((f) =>
    f.patterns.some((p) => p.subtype === 'identity_recon_exfil')
  );

  const confidenceScore = Math.max(50, Math.min(100, baseScore));

  function confidenceLabel(score) {
    if (score >= 95) {
      return 'CRITICAL';
    }
    if (score >= 80) {
      return 'HIGH';
    }
    return 'MEDIUM';
  }

  const evidenceSet = new Set(allEvidence);
  const evidence = [...evidenceSet].slice(0, 10);

  const locationMap = new Map();
  for (const loc of allLocations) {
    const key = `${loc.file}:${loc.line}:${loc.column}`;
    if (!locationMap.has(key)) {
      locationMap.set(key, loc);
    }
  }

  const isCritical = anyCredPattern;
  const severity = isCritical ? 'critical' : confidenceScore >= 80 ? 'high' : 'medium';

  const _domainSummary = filesWithPatterns
    .flatMap((f) => f.domainsFound)
    .filter(Boolean)
    .slice(0, 3);

  const credCount = filesWithPatterns.reduce((s, f) => s + f.credsFound.length, 0);

  let message;
  if (anyCredPattern) {
    message = `Hardcoded credentials detected (${credCount} found)`;
  } else if (anyIdentityRecon) {
    message = 'Identity/credential-adjacent file reconnaissance detected';
  } else if (involvedFiles.length > 1) {
    message = `Cross-file exfiltration detected across ${involvedFiles.length} files`;
  } else if (mainSubtype === 'env_dump') {
    message = 'Environment variable harvesting detected';
  } else {
    message = 'Filesystem exfiltration to external domain detected';
  }

  return [
    {
      detector: 'tier1-infostealer',
      id: 'TIER1-INFOSTEALER',
      severity,
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype: mainSubtype || 'fs_exfil',
      message,
      evidence,
      locations: [...locationMap.values()],
      crossFiles: [...new Set(involvedFiles)],
      reference: 'Campaign 2 & 3',
    },
  ];
}
