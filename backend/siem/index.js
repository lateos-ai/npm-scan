import { generateCEF } from './cef.js';
import { generateECS } from './ecs.js';
import { generateSentinel } from './sentinel.js';
import { generateQRadar } from './qradar.js';

export function generateSIEM(scans, format = 'cef') {
  switch (format) {
    case 'cef':
      return generateCEF(scans);
    case 'ecs':
      return generateECS(scans);
    case 'sentinel':
      return generateSentinel(scans);
    case 'qradar':
      return generateQRadar(scans);
    default:
      throw new Error(`Unknown SIEM format: ${format}. Supported: cef, ecs, sentinel, qradar`);
  }
}