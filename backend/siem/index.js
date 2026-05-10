import { generateCEF } from './cef.js';

export function generateSIEM(scans, format = 'cef') {
  switch (format) {
    case 'cef':
      return generateCEF(scans);
    default:
      throw new Error(`Unknown SIEM format: ${format}`);
  }
}