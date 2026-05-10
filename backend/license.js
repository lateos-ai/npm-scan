export function validateLicense(key, feature = '*') {
  if (!key || !key.startsWith('npm-scan-premium-')) {
    throw new Error(`Invalid license for feature: ${feature}`);
  }
  return true;
}

export function isFeatureEnabled(feature, licenseKey = process.env.NPM_SCAN_LICENSE_KEY) {
  try {
    return validateLicense(licenseKey, feature);
  } catch {
    return false;
  }
}