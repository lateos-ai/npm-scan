/**
 * Detector confidence thresholds (calibrated post-validation)
 *
 * Format: { detector: { flag_threshold, warn_threshold } }
 * Thresholds calibrated against:
 *   - 3 real May 2026 attack campaigns (validation)
 *   - Top 1,000 npm packages (false positive calibration)
 */

export default {
  'TIER1-VERSION-ANOMALY': {
    flag_threshold: 72,
    warn_threshold: 60,
    notes:
      'Sentinel patterns (99.99.99/11.11.11/10.10.10) always flag at 92 regardless of threshold',
  },
  'TIER1-OBFUSCATION-HEURISTICS': {
    flag_threshold: 75,
    warn_threshold: 60,
    notes: 'Increased from 70 post-FP analysis; bundlers (webpack, terser) exempt via whitelist',
  },
  'TIER1-BINARY-EMBED': {
    flag_threshold: 80,
    warn_threshold: 65,
    notes:
      'High threshold justified; platform-specific binary sets are rare in legitimate packages',
  },
  'TIER1-LIFECYCLE-HOOK': {
    flag_threshold: 65,
    warn_threshold: 50,
    notes: 'Moderate threshold; lifecycle hooks common but uncommon in top 1K packages',
  },
  'TIER1-INFOSTEALER': {
    flag_threshold: 72,
    warn_threshold: 55,
    notes: 'Pattern-based; calibrated for C2 signatures, credential exfil patterns',
  },
  'TIER1-TYPOSQUAT': {
    flag_threshold: 85,
    warn_threshold: 70,
    notes:
      'Calibrated to 85 post-FP analysis on top 1,000 packages; 46 edit-distance=1 FPs eliminated at this threshold',
  },
  'TIER1-METADATA-SPOOF': {
    flag_threshold: 70,
    warn_threshold: 55,
    notes: 'Namespace/repo URL spoofing; moderate threshold for legitimate clones',
  },
  'TIER1-VERSION-CONFUSION': {
    flag_threshold: 75,
    warn_threshold: 60,
    notes: 'High-version heuristics (major >= 9); tuned to avoid FP on pre-release tags',
  },
  'TIER1-CLOUD-IMDS': {
    flag_threshold: 80,
    warn_threshold: 65,
    notes: 'IMDS endpoint targeting is rarely legitimate; high threshold',
  },
  'TIER1-MULTISTAGE-POSTINSTALL': {
    flag_threshold: 75,
    warn_threshold: 60,
    notes: 'Two-stage download+exec patterns; moderate threshold',
  },
  'TIER1-SLSA-ATTESTATION': {
    flag_threshold: 85,
    warn_threshold: 70,
    notes:
      'Structural provenance check only (no signature/chain/Rekor verification), so it never grants trust. Actionable outputs are digest_unbound and subject_mismatch (high); presence/absence of provenance is informational (low). Revisit thresholds when cryptographic verification lands.',
  },
  'TIER1-SELF-PROPAGATION': {
    flag_threshold: 75,
    warn_threshold: 60,
    burst_window_minutes: 60,
    min_packages_burst: 3,
    identical_payload_weight: 40,
    notes: 'D10: Detects burst republish patterns (Miasma campaign)',
  },
  'TIER1-ENCRYPTED-C2': {
    flag_threshold: 70,
    warn_threshold: 50,
    known_c2_endpoints: [
      'filev2.getsession.org',
      'api.signal.org',
      '*.briarproject.org',
      'api.ricochet.im',
    ],
    onion_pattern_weight: 30,
    encoded_url_weight: 35,
    env_var_c2_weight: 40,
    notes: 'D11: Detects Session/Oxen, Signal, Briar, Tor C2 channels',
  },
  'TIER1-TRANSITIVE-DEPS': {
    flag_threshold: 80,
    warn_threshold: 50,
    new_package_days: 7,
    unknown_depth_weight: 45,
    typosquat_depth_weight: 50,
    different_maintainer_weight: 35,
    notes: 'D12: Deep dependency tree analysis for injection attacks',
  },
  'TIER1-MAINTAINER-COMPROMISE': {
    flag_threshold: 75,
    warn_threshold: 60,
    velocity_burst_multiplier: 5,
    burst_window_hours: 24,
    min_velocity_baseline: 0.5,
    duplicate_version_weight: 40,
    unusual_timing_weight: 25,
    cross_package_burst_weight: 50,
    single_version_gap_days: 30,
    single_version_remediation_hours: 24,
    dist_tag_rapid_succession_hours: 1,
    notes:
      'D13: Version velocity anomaly and maintainer compromise detection. Extended with single_version_compromise (30+ day gap, deprecated, remediated within 24h) and dist_tag_manipulation (tag repointed to version with next version within 1h).',
  },
  'D15-MEMORY-EXTRACTION': {
    flag_threshold: 75,
    warn_threshold: 55,
    pattern_weights: {
      oidc_token_access: 60,
      memory_introspection: 55,
    },
    pattern_confidence: {
      oidc_token_access: 0.95,
      memory_introspection: 0.9,
    },
    notes: 'D15: Memory Credential Extraction (Miasma Escalated)',
  },
  'D16-EBPF-ROOTKIT': {
    flag_threshold: 100,
    warn_threshold: 70,
    pattern_weights: {
      ebpf_bytecode: 70,
      bpf_syscall: 65,
      kernel_hook: 70,
      syscall_hook: 75,
      hiding_intent: 50,
      kernel_ffi: 50,
    },
    pattern_confidence: {
      ebpf_bytecode: 0.95,
      bpf_syscall: 0.9,
      kernel_hook: 0.95,
      syscall_hook: 0.98,
      hiding_intent: 0.8,
      kernel_ffi: 0.8,
    },
    notes: 'D16: eBPF Rootkit Detection (IronWorm)',
  },
  'D17-PRIVILEGE-ESCALATION': {
    flag_threshold: 120,
    warn_threshold: 70,
    pattern_weights: {
      capability_request: 70,
      exploit_reference: 20,
      setuid_attempt: 65,
      sudo_bypass: 75,
      kernel_memory_access: 70,
      kernel_module_load: 80,
    },
    pattern_confidence: {
      capability_request: 0.95,
      exploit_reference: 0.9,
      setuid_attempt: 0.95,
      sudo_bypass: 0.98,
      kernel_memory_access: 0.95,
      kernel_module_load: 0.98,
    },
    notes: 'D17: Privilege Escalation Patterns (Miasma + IronWorm)',
  },
  'D14-BUILD-CONFIG-ABUSE': {
    flag_threshold: 70,
    warn_threshold: 50,
    pattern_weights: {
      shell_exec: 50,
      process_spawn: 45,
      env_access: 35,
      fs_access: 40,
      http_request: 50,
      path_traversal: 55,
      hardcoded_key: 60,
      getenv_call: 35,
      curl_call: 45,
      execve_call: 55,
      credential_scan: 50,
      socket_call: 40,
      environ_access: 35,
      compile_macro_injection: 60,
      include_path_manipulation: 55,
      linker_library_injection: 50,
      makefile_shell_exec: 55,
      cmake_execute_process: 55,
    },
    legitimate_native_addons: [
      'node-sass',
      'sqlite3',
      'bcrypt',
      '@mapbox/node-pre-gyp',
      'better-sqlite3',
      'sharp',
      'canvas',
      'node-gyp',
      'prebuild-install',
    ],
    pattern_confidence: {
      hardcoded_key: 0.95,
      execve_call: 0.9,
      socket_call: 0.75,
      env_access: 0.6,
      getenv_call: 0.7,
      curl_call: 0.85,
      compile_macro_injection: 0.9,
      makefile_shell_exec: 0.9,
      cmake_execute_process: 0.85,
    },
    max_binary_size_bytes: 10 * 1024 * 1024,
    binary_size_weight: 30,
    binary_age_mismatch_days: 30,
    undeclared_gyp_weight: 45,
    known_reputable_packages: [
      'electron',
      'puppeteer',
      'playwright',
      'sharp',
      'esbuild',
      'node-gyp',
      '@mapbox/node-pre-gyp',
      'node-pre-gyp',
      'webpack',
      'vite',
      'rollup',
    ],
    notes:
      'D14: Build Configuration Abuse (Phantom Gyp / Miasma variant) — enhanced with GypParser, build file analysis, lifecycle hook cross-reference',
  },
  'D18-SELF-DEFENDING': {
    flag_threshold: 170,
    warn_threshold: 120,
    pattern_weights: {
      debugger_detection: 30,
      execution_guard: 35,
      package_validation: 8,
      environment_detection: 25,
      anti_tamper: 65,
      file_modification_detection: 20,
    },
    pattern_confidence: {
      debugger_detection: 0.8,
      execution_guard: 0.85,
      anti_tamper: 0.9,
    },
    notes: 'D18: Self-Defending/Environment-Aware Malicious Code; file_mod_detection weight 20',
  },
  'D19-MODULE-LOAD': {
    flag_threshold: 160,
    warn_threshold: 120,
    pattern_weights: {
      iife_pattern: 35,
      toplevel_await: 45,
      module_hook: 40,
      constructor_execution: 50,
    },
    pattern_confidence: {
      iife_pattern: 0.6,
      toplevel_await: 0.7,
      constructor_execution: 0.85,
    },
    notes: 'D19: Module-Load Execution at Install Time',
  },
  'D20-PROFILING-RECON': {
    flag_threshold: 170,
    warn_threshold: 120,
    pattern_weights: {
      platform_enumeration: 20,
      user_enumeration: 25,
      network_check: 25,
      cloud_detection: 45,
      directory_scan: 20,
      tools_detection: 25,
    },
    pattern_confidence: {
      platform_enumeration: 0.6,
      user_enumeration: 0.65,
      cloud_detection: 0.8,
    },
    notes:
      'D20: Profiling & Reconnaissance; weights lowered for platform_enum + user_enum + dir_scan',
  },
  'D21-SELF-CLEANING': {
    flag_threshold: 180,
    warn_threshold: 120,
    pattern_weights: {
      self_deletion: 85,
      package_json_manipulation: 75,
      file_swap: 60,
      log_cache_clear: 45,
      git_history_removal: 70,
      timestamp_manipulation: 50,
    },
    pattern_confidence: {
      self_deletion: 0.99,
      package_json_manipulation: 0.95,
      git_history_removal: 0.95,
    },
    notes: 'D21: Self-Cleaning / Evidence Removal',
  },
  'D22-AI-TOKEN-TARGETING': {
    flag_threshold: 80,
    warn_threshold: 60,
    pattern_weights: {
      claude_token_targeting: 90,
      openai_token_targeting: 90,
      gemini_token_targeting: 85,
      mistral_token_targeting: 85,
      openrouter_token_targeting: 80,
      slack_token_targeting: 75,
      sendgrid_token_targeting: 75,
      google_api_key_targeting: 75,
      cursor_token_targeting: 85,
      ai_config_targeting: 80,
      ai_token_exfiltration: 95,
      ai_platform_enumeration: 75,
    },
    pattern_confidence: {
      ai_token_exfiltration: 0.99,
      claude_token_targeting: 0.98,
      openai_token_targeting: 0.98,
      ai_config_targeting: 0.98,
      gemini_token_targeting: 0.95,
      mistral_token_targeting: 0.95,
      cursor_token_targeting: 0.95,
      ai_platform_enumeration: 0.9,
    },
    notes: 'D22: AI Token Targeting (IronWorm AI-targeted infostealer patterns)',
  },
  'D23-GITHUB-AUTHOR-SPOOF': {
    flag_threshold: 85,
    warn_threshold: 65,
    pattern_weights: {
      github_author_spoof: 95,
      spoofed_git_commit: 90,
      force_push: 40,
      force_push_lease: 30,
      ai_workflow_impersonation: 80,
      full_author_spoof_attack: 99,
      authenticated_spoof_push: 95,
      repo_hijacking: 85,
    },
    pattern_confidence: {
      full_author_spoof_attack: 0.99,
      authenticated_spoof_push: 0.99,
      github_author_spoof: 0.99,
      spoofed_git_commit: 0.99,
      force_push: 0.95,
      repo_hijacking: 0.9,
      ai_workflow_impersonation: 0.9,
      force_push_lease: 0.85,
    },
    notes: 'D23: GitHub Author Spoof (claude@/gpt@ noreply impersonation, IronWorm)',
  },
  'D24-BUN-RUNTIME-SWAP': {
    enabled: true,
    flag_threshold: 80,
    warn_threshold: 60,
    pattern_weights: {
      bun_credential_combo: 95,
      bun_binary_execution: 85,
      bun_downloader: 90,
      bun_api_usage: 75,
      process_argv_swap: 80,
      node_to_bun_swap: 90,
    },
    notes: 'D24: Bun Runtime Swap (Miasma/Hades campaign)',
  },
  'D25-SPLIT-DYNAMIC-PAYLOAD': {
    enabled: true,
    flag_threshold: 80,
    warn_threshold: 60,
    pattern_weights: {
      payload_assembly_chain: 99,
      eval_with_fetched_code: 95,
      syspath_searching: 85,
      dynamic_require: 80,
      buffer_assembly: 80,
      multifile_traversal: 75,
      obfuscated_assembly: 70,
      dynamic_discovery: 70,
    },
    notes: 'D25: Split/Dynamic Payload (Miasma/Hades campaign)',
  },
  'TIER1-HOOK-FOLLOWTHROUGH': {
    flag_threshold: 70,
    warn_threshold: 55,
    notes:
      'Follows node/sh/bash indirection in lifecycle hooks to referenced files; chains up to 2 levels',
  },
  'TIER1-VERSION-BACKFILL': {
    flag_threshold: 80,
    warn_threshold: 65,
    min_versions: 8,
    max_spread_hours: 24,
    notes: 'Detects version history backfilled in a single publish burst to fake package maturity',
  },
  'TIER1-CRYPTO-TAMPER': {
    flag_threshold: 85,
    warn_threshold: 70,
    notes:
      'Diff-aware detection of semantic backdoors in crypto/wallet primitives. Compares security-sensitive functions (fromMnemonic, sign, etc.) against previous version to detect newly injected network calls or dynamic code execution. High threshold justified by diff-awareness eliminating FPs from legitimate telemetry.',
  },
  'PROMPT-INJECTION': {
    flag_threshold: 80,
    warn_threshold: 60,
    pattern_weights: {
      instruction_override: 75,
      command_execution: 95,
      data_exfiltration_context: 85,
      hidden_directives: 70,
    },
    notes:
      'D26: Detects prompt injection patterns in LLM/AI agent context files (.cursorrules, CLAUDE.md, AGENTS.md). Command execution patterns always flag critical.',
  },
  'TIER1-WORM-PROPAGATION': {
    flag_threshold: 80,
    warn_threshold: 60,
    pattern_weights: {
      npmrc_exfil: 95,
      github_ssh_exfil: 95,
      cloud_cred_exfil: 90,
      self_publish: 85,
      immediate_exfil_no_delay: 90,
    },
    pattern_confidence: {
      npmrc_exfil: 0.98,
      github_ssh_exfil: 0.98,
      cloud_cred_exfil: 0.95,
      self_publish: 0.9,
      immediate_exfil_no_delay: 0.85,
    },
    notes:
      'D27: Detects static patterns enabling ultra-fast wormable self-propagation (credential scraping + auto-publish capability in install-time code).',
  },
  'D28-AI-SLOP-DROPPER': {
    enabled: true,
    flag_threshold: 80,
    warn_threshold: 55,
    // Calibrated against the 50-package clean corpus with the reputable-package
    // bail defeated. Literals >= 64 chars: 1050 clean literals exceed 4.5 bits
    // (prettier's HTML attribute tables peak at 4.76), so the 4.5 the campaign
    // write-up suggests is too low. Random base64 payloads score 5.0-5.4.
    entropy_threshold: 5.0,
    min_literal_length: 64,
    min_high_entropy_literals: 3,
    // A base64 *shape* test alone matches ordinary camelCase identifiers
    // ('doExpressions', 'RegExpLiteral'). Of 12,708 base64-shaped literals in
    // the clean corpus only 43 reach 4.5 bits, so the entropy gate is what
    // separates encoded payloads from identifier arrays.
    base64_min_length: 16,
    base64_min_entropy: 4.5,
    min_encoded_array_size: 8,
    encoded_array_ratio: 0.8,
    max_file_bytes: 512000,
    // Only anchor_signals can justify a finding on their own. The supporting
    // signals raise severity but never fire alone — Next.js couples
    // process.platform with its dev-server network code, and prebuilt-binary
    // installers pair platform/arch with an HTTP fetch by design.
    anchor_signals: ['dns_payload_assembly', 'dns_txt_oob', 'encoded_string_array'],
    pattern_weights: {
      dns_payload_assembly: 95,
      encoded_string_array: 60,
      dns_txt_oob: 55,
      string_array_decoder: 50,
      fingerprint_network_coupling: 40,
      readme_directed_entry: 30,
      high_entropy_literals: 20,
      paas_stage_resolution: 20,
      env_fingerprint: 10,
    },
    // DNS TXT/ANY lookups are the documented job of these packages, so the
    // dns_txt_oob signal is suppressed for them. dns_payload_assembly is never
    // suppressed — decoding TXT records into executable code is not legitimate
    // even for a mail utility.
    network_utility_safelist: [
      'dns2',
      'native-dns',
      'dns-packet',
      'dns-socket',
      'dig.js',
      'nodemailer',
      'mailauth',
      'spf-check',
      'spf-record-check',
      'dkim-signer',
      'mailparser',
      'acme-client',
      'greenlock',
      'node-dig-dns',
      'whois',
      'is-online',
    ],
    network_utility_keywords: [
      'dns',
      'spf',
      'dkim',
      'dmarc',
      'mx record',
      'whois',
      'resolver',
      'nameserver',
      'smtp',
      'acme',
      'letsencrypt',
    ],
    notes:
      'D28: "AI Slop" / WEL1DROPPER 800-package campaign. README-directed require()/import entry (no lifecycle hooks) + hex/base64 string-array obfuscation + process.platform/arch fingerprinting coupled to out-of-band DNS TXT stage-2 resolution. Findings require an anchor signal; supporting signals only modulate severity. dns_txt_oob is suppressed for genuine DNS/mail utilities (network_utility_safelist/keywords); dns_payload_assembly never is. Verified 0 FPs across the 50-package clean corpus with the reputable-package bail defeated.',
  },
  'D29-RUNTIME-EVASION': {
    enabled: true,
    flag_threshold: 80,
    warn_threshold: 55,
    max_file_bytes: 512000,
    // Only anchor signals can justify a finding. Everything else is something
    // legitimate Bun/Deno tooling does routinely — Bun.file and Bun.serve are
    // the ordinary way to write a Bun HTTP server, and a runtime fingerprint is
    // how cross-runtime libraries pick a code path. Gating on execution,
    // native linking and runtime downloads is what keeps this detector off
    // honest Bun-based packages, and it also corrects D24's inverted coverage,
    // where the four *benign* primitives were the four that fired.
    anchor_signals: [
      'runtime_download_install_time',
      'runtime_download',
      'alt_runtime_exec_entry',
      'alt_runtime_exec',
      'alt_runtime_ffi',
      'alt_runtime_hook_interpreter',
    ],
    pattern_weights: {
      runtime_download_install_time: 90,
      alt_runtime_ffi: 80,
      alt_runtime_exec_entry: 70,
      runtime_download: 60,
      alt_runtime_credential_access: 55,
      alt_runtime_exec: 50,
      // At or above warn_threshold on purpose: this is an anchor signal, and an
      // anchor weighted below the threshold can never fire on its own.
      alt_runtime_hook_interpreter: 55,
      alt_runtime_network_entry: 35,
      alt_runtime_network: 25,
      alt_runtime_env_read: 20,
      alt_runtime_listen: 15,
      alt_runtime_fs_read: 15,
      runtime_fingerprint: 10,
      unparsable_source: 15,
    },
    notes:
      'D29: alternative-runtime evasion (Bun/Deno/QuickJS). Closes the gap where a Deno-idiom credential stealer scored zero findings while the byte-identical Node version scored HIGH. Capability classification is delegated to lib/runtime-primitives.js so adding a runtime is a registry edit. Weights are pre-telemetry and calibrated against the gap-analysis PoCs only — retune once production scan data exists, particularly alt_runtime_network and alt_runtime_fs_read, which legitimate Bun tooling triggers.',
  },
  'D30-WORKSPACE-PERSISTENCE': {
    enabled: true,
    flag_threshold: 80,
    warn_threshold: 45,
    max_file_bytes: 512000,
    // Severity follows the surface band, not the syntax. An injected
    // instruction needs an agent to comply (high); an injected server command
    // executes unconditionally on the next agent/editor start (critical).
    band_weights: {
      exec: 30,
      agent_read: 15,
      editor_config: 0,
    },
    pattern_weights: {
      shipped_workflow_secret_exfil: 90,
      shipped_workflow_privileged_trigger: 70,
      shipped_exec_config: 65,
      dynamic_surface_write: 55,
      static_surface_write: 40,
    },
    notes:
      'D30: agent/IDE workspace persistence. Paths are constant-folded through lib/path-resolver.js before matching, so dynamic assembly (Array.join, path.join, String.fromCharCode, template literals) resolves to the same target as a literal. Replaces ATK-004 coverage, which required a literal "mkdir" token on the same line as the directory name. Packages that legitimately declare themselves MCP servers are suppressed unless the config launches a shell, passes an inline -c payload, or fetches from the network.',
  },
  'D31-TARBALL-GIT-DESYNC': {
    // OFF BY DEFAULT. This is the only network-bound detector in the suite: it
    // fetches the repository tree for the attested commit or release tag. The
    // scan pipeline short-circuits before any I/O when disabled, so the
    // default path carries no added cost. Enable per-scan via options, or flip
    // this flag in a deployment that accepts the latency.
    enabled: false,
    // When enabled but the source cannot be fetched, emit an informational
    // finding rather than silence — "not compared" must not read as "clean".
    report_unverifiable: true,
    timeout_ms: 8000,
    notes:
      'D31: tarball-to-git differential (ERR_TARBALL_GIT_DESYNC). Answers the question provenance cannot: npm attestations bind an attestation to a tarball, never a tarball to its source, so a build from a dirty working tree produces a genuine attestation with a perfectly matching digest. Provenance state is deliberately never consulted — a valid attestation over tampered output is the attack. Build-output directories are skipped rather than treated as clean, and the skip count is reported so callers can distinguish verified from unchecked.',
  },
  'D32-HOST-PERSISTENCE': {
    enabled: true,
    flag_threshold: 80,
    warn_threshold: 60,
    max_file_bytes: 512000,
    anchor_signals: [
      'deadman_switch',
      'launch_agent_user',
      'loginctl_linger',
      'systemd_user_unit',
      'launchctl_plist_write',
    ],
    pattern_weights: {
      deadman_switch: 95,
      launch_agent_user: 85,
      loginctl_linger: 85,
      systemd_user_unit: 80,
      launchctl_plist_write: 75,
      self_destruct_threshold: 65,
      token_monitor_poll: 60,
    },
    notes:
      'D32: user-level host persistence + dead-man switch (keyv/cacheable, 2026-08). Complements msh D2 / axios D3, which cover only SYSTEM units (/etc/systemd/system, /Library/LaunchDaemons). A finding requires an anchor (an autostart install or the dead-man switch); token_monitor_poll and self_destruct_threshold only modulate. The dead-man switch is AST-gated so eval("literal") never fires — only eval/exec of a variable-supplied handler correlated with a credential-revocation check. Weights are pre-telemetry; retune on the Linux corpus before trusting FP numbers.',
  },
  'D33-INSTALL-CONFIG-ABUSE': {
    enabled: true,
    flag_threshold: 80,
    warn_threshold: 60,
    pattern_weights: {
      pnpmfile_mutates_and_dispatches: 85,
      yarnrc_external_plugin: 80,
      bunfig_preload: 75,
      pnpmfile_dispatch: 70,
      override_resolved_off_registry: 80,
      bunfig_trusted_dependencies: 55,
    },
    notes:
      'D33: install-time execution outside package.json scripts (gap-analysis-2026-08 §5). .pnpmfile.cjs readPackage hooks, .yarnrc(.yml) plugins, bunfig.toml preload/trustedDependencies, and package.json overrides/resolutions. Presence of a .pnpmfile.cjs is not suspicious on its own — a benign monorepo hook scores nothing; only hooks that reach outside the package (exec/network) or rewrite a dependency fire. overrides/resolutions flag only off-registry protocols (git+ssh/ssh/http/file/link); github:/git+https:/npm: aliasing is too common to flag.',
  },
  'TIER1-MANIFEST-CONFUSION': {
    enabled: true,
    flag_threshold: 85,
    warn_threshold: 70,
    pattern_weights: {
      dependency_divergence: 90,
      optional_dependency_divergence: 85,
      peer_dependency_divergence: 80,
      script_divergence: 100,
      bin_divergence: 90,
    },
    notes:
      'D34: registry version manifest vs tarball package.json. The two come from the same publish, so any divergence in a capability-bearing field (dependencies, optionalDependencies, peerDependencies, scripts, bin) has no benign explanation. Registry-injected fields (_id, dist, _npmUser, gitHead, …) are stripped before diffing; a lifecycle hook present only in the tarball is always critical. Returns [] when registryMeta is absent (local --file scans).',
  },
  SERVERLESS_PAAS_WATCHLIST: {
    domains: ['*.run.app', '*.web.app', '*.vercel.app', '*.netlify.app', '*.workers.dev'],
    confidence_boost: 15,
    notes:
      'Serverless PaaS destinations as contributing signal when appearing in lifecycle hooks or install scripts; not standalone critical',
  },
};
