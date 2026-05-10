import { createHmac, timingSafeEqual } from 'crypto';

const HMAC_KEY = process.env.NPM_SCAN_LICENSE_SECRET || 'npm-scan-default-dev-key';

const FEATURE_TIERS = {
  community: [],
  premium: ['sandbox', 'siem', 'cra', 'nist-pdf', 'rest-api', 'webhooks', 'helm'],
  enterprise: ['sandbox', 'siem', 'cra', 'nist-pdf', 'rest-api', 'webhooks', 'helm', 'sso', 'audit-logs', 'pg-backend', 'kubernetes'],
};

const ALL_FEATURES = Object.values(FEATURE_TIERS).flat();
const ALLOWED_UNLOCKED = ['sbom', 'nist-html', 'html-report', 'sqlite'];

function generateSignature(payload) {
  return createHmac('sha256', HMAC_KEY).update(JSON.stringify(payload)).digest('hex');
}

export function generateKey(edition, options = {}) {
  const payload = {
    edition,
    issued: new Date().toISOString(),
    exp: options.expiresAt || null,
    seats: options.seats || 1,
    org: options.org || null,
  };
  const sig = generateSignature(payload);
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `npm-scan-${edition}-${encoded}.${sig}`;
}

export function validateLicense(key, feature = '*') {
  if (!key) {
    throw new Error('No license key provided');
  }

  if (feature === 'scan' || ALLOWED_UNLOCKED.includes(feature)) {
    return { edition: 'community', features: ALL_FEATURES };
  }

  const parts = key.split('-');
  if (parts.length < 4 || !key.includes('.')) {
    throw new Error('Invalid license key format');
  }

  const edition = parts[2];
  const encodedPayload = parts.slice(3).join('-').split('.')[0];
  const sig = key.split('.')[1];

  let payload;
  try {
    payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  } catch {
    throw new Error('Invalid license key payload');
  }

  const expectedSig = generateSignature(payload);
  const sigBuf = Buffer.from(sig, 'hex');
  const expectedBuf = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
    throw new Error('Invalid license key signature');
  }

  if (payload.exp && new Date(payload.exp) < new Date()) {
    throw new Error('License key expired');
  }

  const allowed = FEATURE_TIERS[edition];
  if (!allowed) {
    throw new Error(`Unknown license edition: ${edition}`);
  }

  if (feature !== '*' && !allowed.includes(feature) && !ALLOWED_UNLOCKED.includes(feature)) {
    throw new Error(`Feature "${feature}" requires ${edition === 'community' ? 'premium' : 'enterprise'} license`);
  }

  return { edition, features: allowed, ...payload };
}

export function isFeatureEnabled(feature, licenseKey = process.env.NPM_SCAN_LICENSE_KEY) {
  try {
    validateLicense(licenseKey, feature);
    return true;
  } catch {
    return false;
  }
}