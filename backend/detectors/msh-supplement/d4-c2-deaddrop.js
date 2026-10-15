const OHNO_WHATS_GOING_ON_RE = /OhNoWhatsGoingOnWithGitHub/;
const GITHUB_COMMIT_SCRAPE_RE = /api\.github\.com\/repos\/[^/]+\/[^/]+\/commits/;
const GITHUB_GRAPHQL_RE = /api\.github\.com\/graphql/;
const GITHUB_TOKEN_ACCESS_RE = /process\.env\.(?:GH_TOKEN|GITHUB_TOKEN|GITHUB_ACTOR)/;
const COMMIT_PARSE_LOOP_RE = /commits?\s*\.\s*(?:map|filter|forEach|for\s*\(|while\s*\()/;

// PolinRider-class on-chain dead-drop (EtherHiding / NullReceiver): the C2 or
// stage-2 payload is resolved from blockchain storage or transaction data
// rather than a DNS record or a GitHub commit.
const ETH_RPC_METHOD_RE =
  /\b(?:eth_call|eth_getStorageAt|eth_getTransactionByHash|eth_getTransactionReceipt|eth_getLogs)\b/;
const ETH_PROVIDER_RE =
  /infura\.io|alchemyapi\.io|alchemy\.com|api\.etherscan\.io|etherscan\.io|\/rpc\b|sepolia|mainnet|ropsten|goerli/i;
const WEB3_LIB_RE =
  /require\(\s*['"](?:ethers|web3)['"]\s*\)|from\s+['"](?:ethers|web3)['"]|new\s+(?:ethers|web3)\s*[.(]/i;
const HEX_ADDRESS_RE = /0x[a-fA-F0-9]{40}/;

function scanBlockchainDeadDrop(code) {
  const hasRpc = ETH_RPC_METHOD_RE.test(code);
  const hasProvider = ETH_PROVIDER_RE.test(code);
  const hasLib = WEB3_LIB_RE.test(code);
  const hasAddr = HEX_ADDRESS_RE.test(code);
  if ((hasRpc && (hasProvider || hasAddr)) || (hasLib && hasAddr && hasRpc)) {
    return {
      type: 'blockchain_dead_drop',
      value: 'on-chain dead-drop (EtherHiding/NullReceiver)',
      attackVector: 'C2 or stage-2 payload resolved from blockchain storage/transaction data',
    };
  }
  return null;
}

export function scanC2DeadDrop(files = []) {
  const code = files.map((f) => f.content || '').join('\n');
  if (!code) {
    return { triggered: false, matches: [] };
  }

  const matches = [];

  if (OHNO_WHATS_GOING_ON_RE.test(code)) {
    matches.push({
      type: 'ioc_keyword',
      value: 'OhNoWhatsGoingOnWithGitHub',
      attackVector: 'GitHub commit scraping for token recovery',
    });
  }

  const hasTokenAccess = GITHUB_TOKEN_ACCESS_RE.test(code);
  const hasGithubApi = GITHUB_COMMIT_SCRAPE_RE.test(code) || GITHUB_GRAPHQL_RE.test(code);
  const hasCommitParseLoop = COMMIT_PARSE_LOOP_RE.test(code);

  if (hasTokenAccess && hasGithubApi) {
    matches.push({
      type: 'token_exfil_github_api',
      value: 'Credential access followed by GitHub API call',
      attackVector: 'Credential/token extraction followed by GitHub API calls',
    });
  }

  if (hasCommitParseLoop && hasGithubApi) {
    matches.push({
      type: 'commit_scraping',
      value: 'Commit message parsing with GitHub API',
      attackVector: 'Commit scraping for secret detection',
    });
  }

  const chainDrop = scanBlockchainDeadDrop(code);
  if (chainDrop) {
    matches.push(chainDrop);
  }

  return {
    triggered: matches.length > 0,
    matches,
  };
}
