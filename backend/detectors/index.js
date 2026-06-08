import * as atk001 from './atk-001-lifecycle.js';
import * as atk002 from './atk-002-obfusc.js';
import * as atk003 from './atk-003-creds.js';
import * as atk004 from './atk-004-persist.js';
import * as atk005 from './atk-005-exfil.js';
import * as atk006 from './atk-006-depconf.js';
import * as atk007 from './atk-007-typosquat.js';
import * as atk008 from './atk-008-tarball-tamper.js';
import * as atk009 from './atk-009-dormant-trigger.js';
import * as atk010 from './atk-010-sandbox-evasion.js';
import * as atk011 from './atk-011-transitive-prop.js';
import { scanAll as megalodonScan } from './megalodon/index.js';
import { scan as hfScan } from './hf-impersonation/index.js';
import { scan as miniShaiHuludScan } from './mini-shai-hulud/index.js';
import { scan as badhostScan } from './cve-2026-48710-badhost/index.js';
import { scan as trapdoorScan } from './trapdoor/index.js';
import { scan as nodeIpcScan } from './node-ipc-compromise/index.js';
import { scan as mshSupplementScan } from './msh-supplement/index.js';
import { scan as typosquatScan } from './typosquat-vpmdhaj/index.js';
import { scan as axiosPoisoningScan } from './axios-poisoning/index.js';
import { scan as tier1TyposquatScan } from './tier1-typosquat.js';
import { scan as tier1InfostealerScan } from './tier1-infostealer.js';
import { scan as tier1LifecycleHookScan } from './tier1-lifecycle-hook.js';
import { scan as tier1BinaryEmbedScan } from './tier1-binary-embed.js';
import { scan as tier1MetadataSpoofScan } from './tier1-metadata-spoof.js';
import { scan as tier1VersionConfusionScan } from './tier1-version-confusion.js';
import { scan as tier1CloudImdsScan } from './tier1-cloud-imds.js';
import { scan as tier1MultistagePostinstallScan } from './tier1-multistage-postinstall.js';
import { scan as tier1VersionAnomalyScan } from './tier1-version-anomaly.js';
import { scan as tier1ObfuscationHeuristicsScan } from './tier1-obfuscation-heuristics.js';
import { scan as tier1SlsaAttestationScan } from './tier1-slsa-attestation.js';
import { scan as tier1SelfPropagationScan } from './tier1-self-propagation.js';
import { scan as tier1EncryptedC2Scan } from './tier1-encrypted-c2.js';
import { scan as tier1TransitiveDepsScan } from './tier1-transitive-deps.js';
import { scan as tier1MaintainerCompromiseScan } from './tier1-maintainer-compromise.js';
import { scan as tier1BuildConfigAbuseScan } from './tier1-build-config-abuse.js';
import { scan as tier1MemoryExtractionScan } from './tier1-memory-extraction.js';
import { scan as tier1EbpfRootkitScan } from './tier1-ebpf-rootkit.js';
import { scan as tier1PrivilegeEscalationScan } from './tier1-privilege-escalation.js';
import { scan as tier1SelfDefendingScan } from './tier1-self-defending.js';
import { scan as tier1ModuleLoadScan } from './tier1-module-load.js';
import { scan as tier1ProfilingReconScan } from './tier1-profiling-recon.js';
import { scan as tier1SelfCleaningScan } from './tier1-self-cleaning.js';
import { scan as tier1AiTokenTargetingScan } from './tier1-ai-token-targeting.js';
import { scan as tier1GitHubAuthorSpoofScan } from './tier1-github-author-spoof.js';

function timeout(ms) {
  return new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`timeout after ${ms}ms`)), ms)
  );
}

async function runTier1(name, scanFn, pkgJson, files, registryMeta, allFiles) {
  try {
    const result = await Promise.race([
      scanFn(pkgJson, files, registryMeta, allFiles),
      timeout(800),
    ]);
    const fileCount = allFiles && allFiles.length > 0 ? allFiles.length : files.length;
    if (fileCount >= 10 && result.length > 0) {
      const hitRate = result.length / fileCount;
      if (hitRate > 0.8) {
        return [];
      }
    }
    return result;
  } catch {
    return [];
  }
}

export async function runAll(pkgJson, files = [], registryMeta = null, allFiles = null) {
  const findings = [];
  findings.push(...(await atk001.scan(pkgJson, files)));
  findings.push(...(await atk002.scan(pkgJson, files)));
  findings.push(...(await atk003.scan(pkgJson, files)));
  findings.push(...(await atk004.scan(pkgJson, files)));
  findings.push(...(await atk005.scan(pkgJson, files)));
  findings.push(...(await atk006.scan(pkgJson, files)));
  findings.push(...(await atk007.scan(pkgJson, files)));
  findings.push(...(await atk008.scan(pkgJson, files)));
  findings.push(...(await atk009.scan(pkgJson, files)));
  findings.push(...(await atk010.scan(pkgJson, files)));
  findings.push(...(await atk011.scan(pkgJson, files)));
  findings.push(...(await megalodonScan(pkgJson, allFiles || files, registryMeta)));
  findings.push(...(await hfScan(pkgJson, files, registryMeta, allFiles || files)));
  findings.push(...(await miniShaiHuludScan(pkgJson, files, registryMeta, allFiles || files)));
  findings.push(...(await badhostScan(pkgJson, files, registryMeta, allFiles || files)));
  findings.push(...(await trapdoorScan(pkgJson, files, registryMeta, allFiles || files)));
  findings.push(...(await nodeIpcScan(pkgJson, files, registryMeta, allFiles || files)));
  findings.push(...(await mshSupplementScan(pkgJson, files, registryMeta, allFiles || files)));
  findings.push(...(await typosquatScan(pkgJson, files, registryMeta, allFiles || files)));
  findings.push(...(await axiosPoisoningScan(pkgJson, files, registryMeta, allFiles || files)));
  findings.push(
    ...(await runTier1(
      'tier1-typosquat',
      tier1TyposquatScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-infostealer',
      tier1InfostealerScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-lifecycle-hook',
      tier1LifecycleHookScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-binary-embed',
      tier1BinaryEmbedScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-metadata-spoof',
      tier1MetadataSpoofScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-version-confusion',
      tier1VersionConfusionScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-cloud-imds',
      tier1CloudImdsScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-multistage-postinstall',
      tier1MultistagePostinstallScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-version-anomaly',
      tier1VersionAnomalyScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-obfuscation-heuristics',
      tier1ObfuscationHeuristicsScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-slsa-attestation',
      tier1SlsaAttestationScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-self-propagation',
      tier1SelfPropagationScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-encrypted-c2',
      tier1EncryptedC2Scan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-transitive-deps',
      tier1TransitiveDepsScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-maintainer-compromise',
      tier1MaintainerCompromiseScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-build-config-abuse',
      tier1BuildConfigAbuseScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-memory-extraction',
      tier1MemoryExtractionScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-ebpf-rootkit',
      tier1EbpfRootkitScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-privilege-escalation',
      tier1PrivilegeEscalationScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-self-defending',
      tier1SelfDefendingScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-module-load',
      tier1ModuleLoadScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-profiling-recon',
      tier1ProfilingReconScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-self-cleaning',
      tier1SelfCleaningScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-ai-token-targeting',
      tier1AiTokenTargetingScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  findings.push(
    ...(await runTier1(
      'tier1-github-author-spoof',
      tier1GitHubAuthorSpoofScan,
      pkgJson,
      files,
      registryMeta,
      allFiles || files
    ))
  );
  return findings.sort((a, b) => b.severity.localeCompare(a.severity));
}
