import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
const SEV_COLORS = { critical: rgb(0.8, 0.2, 0.2), high: rgb(0.75, 0.15, 0.15), medium: rgb(0.9, 0.5, 0.1), low: rgb(0.8, 0.7, 0.1) };

const NIST_SR_MAP = {
  'ATK-001': { control: 'SR-3.1', title: 'Malicious code detection' },
  'ATK-002': { control: 'SR-4.2', title: 'Code obfuscation analysis' },
  'ATK-003': { control: 'SR-5.3', title: 'Credential protection' },
  'ATK-004': { control: 'SR-6.4', title: 'Persistence monitoring' },
  'ATK-005': { control: 'SR-7.5', title: 'Data exfiltration prevention' },
  'ATK-006': { control: 'SR-2.2', title: 'Dependency validation' },
  'ATK-007': { control: 'SR-2.1', title: 'Typosquatting prevention' },
  'ATK-008': { control: 'SR-8.1', title: 'Integrity verification' },
  'ATK-009': { control: 'SR-9.2', title: 'Conditional behavior analysis' },
  'ATK-010': { control: 'SR-10.3', title: 'Anti-evasion detection' },
  'ATK-011': { control: 'SR-11.4', title: 'Supply chain propagation monitoring' },
};

const MARGIN = 50;
const PAGE_W = 612;
const PAGE_H = 792;
const CONTENT_W = PAGE_W - MARGIN * 2;

function wrapText(text, font, size, maxWidth) {
  const words = text.split(' ');
  const lines = [];
  let current = '';
  for (const word of words) {
    const test = current ? current + ' ' + word : word;
    if (font.widthOfTextAtSize(test, size) > maxWidth) {
      if (current) lines.push(current);
      current = word;
    } else {
      current = test;
    }
  }
  if (current) lines.push(current);
  return lines;
}

function drawTableRow(page, font, columns, y, colWidths, fontSize, isHeader) {
  let x = MARGIN;
  const rowH = fontSize + 6;
  for (let i = 0; i < columns.length; i++) {
    const text = columns[i];
    const lines = wrapText(text, font, fontSize, colWidths[i] - 4);
    for (let j = 0; j < lines.length; j++) {
      page.drawText(lines[j], { x: x + 2, y: y - (j * fontSize) - 2, size: fontSize, font, color: rgb(0, 0, 0) });
    }
    x += colWidths[i];
  }
  return y - rowH;
}

function drawPageHeader(page, font, text, y) {
  page.drawText(text, { x: MARGIN, y, size: 14, font, color: rgb(0.2, 0.2, 0.2) });
  page.drawLine({ start: { x: MARGIN, y: y - 4 }, end: { x: PAGE_W - MARGIN, y: y - 4 }, thickness: 1, color: rgb(0.7, 0.7, 0.7) });
  return y - 20;
}

export async function generatePDF(scans) {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const boldFont = await doc.embedFont(StandardFonts.HelveticaBold);
  const version = process.env.npm_package_version || '0.0.0';

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  let totalFindings = 0;
  for (const s of scans) {
    for (const f of (s.findings || [])) {
      if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++;
      totalFindings++;
    }
  }

  // ─── Page 1: Title ──────────────────────────────────────────────────
  let page = doc.addPage([PAGE_W, PAGE_H]);
  let y = PAGE_H - MARGIN;

  page.drawText('npm-scan Report', { x: MARGIN, y, size: 24, font: boldFont, color: rgb(0, 0, 0) });
  y -= 30;
  page.drawText(`Generated: ${new Date().toISOString()}`, { x: MARGIN, y, size: 10, font, color: rgb(0.4, 0.4, 0.4) });
  y -= 14;
  page.drawText(`Version: ${version}  |  Packages scanned: ${scans.length}  |  Total findings: ${totalFindings}`, { x: MARGIN, y, size: 10, font, color: rgb(0.4, 0.4, 0.4) });
  y -= 30;

  // Severity summary
  page.drawText('Severity Summary', { x: MARGIN, y, size: 14, font: boldFont, color: rgb(0, 0, 0) });
  y -= 20;

  for (const sev of SEV_ORDER) {
    const count = sevCounts[sev] || 0;
    const color = SEV_COLORS[sev] || rgb(0, 0, 0);
    page.drawCircle({ x: MARGIN + 6, y: y - 4, size: 4, color });
    page.drawText(`${sev}: ${count}`, { x: MARGIN + 16, y: y - 8, size: 11, font, color: rgb(0, 0, 0) });
    y -= 18;
  }

  y -= 20;

  // Per-package summary
  for (const s of scans) {
    const findings = s.findings || [];
    if (y < MARGIN + 60) { page = doc.addPage([PAGE_W, PAGE_H]); y = PAGE_H - MARGIN; }

    page.drawText(`${s.package_name}@${s.version || 'unknown'}`, { x: MARGIN, y, size: 12, font: boldFont, color: rgb(0, 0, 0) });
    y -= 16;
    page.drawText(`  ${findings.length} findings`, { x: MARGIN, y, size: 10, font, color: rgb(0.4, 0.4, 0.4) });
    y -= 14;

    for (const f of findings) {
      if (y < MARGIN + 20) { page = doc.addPage([PAGE_W, PAGE_H]); y = PAGE_H - MARGIN; }
      const sevColor = SEV_COLORS[f.severity] || rgb(0, 0, 0);
      page.drawCircle({ x: MARGIN + 3, y: y + 2, size: 3, color: sevColor });
      const line = `${f.atk_id || f.id}  ${f.severity}  ${(f.description || f.title || '').slice(0, 70)}`;
      page.drawText(line, { x: MARGIN + 12, y, size: 9, font, color: rgb(0.1, 0.1, 0.1) });
      y -= 13;
    }
  }

  // ─── Page: Findings Table ───────────────────────────────────────────
  page = doc.addPage([PAGE_W, PAGE_H]);
  y = PAGE_H - MARGIN;
  y = drawPageHeader(page, boldFont, 'All Findings', y);
  y -= 6;

  const colWidths = [60, 55, 140, CONTENT_W - 255];
  const headers = ['ATK ID', 'Severity', 'Title', 'Evidence'];

  // Draw header
  let x = MARGIN;
  for (let i = 0; i < headers.length; i++) {
    page.drawText(headers[i], { x: x + 2, y, size: 10, font: boldFont, color: rgb(0, 0, 0) });
    x += colWidths[i];
  }
  y -= 16;

  lineLoop: for (const s of scans) {
    for (const f of (s.findings || [])) {
      if (y < MARGIN + 20) {
        page = doc.addPage([PAGE_W, PAGE_H]);
        y = PAGE_H - MARGIN;
        y = drawPageHeader(page, boldFont, 'All Findings (continued)', y);
        y -= 6;
      }

      const rowData = [
        f.atk_id || f.id || '',
        f.severity || '',
        (f.title || '').slice(0, 30),
        (f.evidence || '').slice(0, 60),
      ];

      let rowY = y;
      let maxLines = 1;
      for (let i = 0; i < rowData.length; i++) {
        const lines = wrapText(rowData[i], font, 9, colWidths[i] - 4);
        if (lines.length > maxLines) maxLines = lines.length;
      }

      if (y - (maxLines * 11) < MARGIN) {
        page = doc.addPage([PAGE_W, PAGE_H]);
        y = PAGE_H - MARGIN;
        y = drawPageHeader(page, boldFont, 'All Findings (continued)', y);
        y -= 6;
        rowY = y;
      }

      x = MARGIN;
      for (let i = 0; i < rowData.length; i++) {
        const lines = wrapText(rowData[i], font, 9, colWidths[i] - 4);
        for (let j = 0; j < lines.length; j++) {
          const color = i === 1 && SEV_COLORS[f.severity] ? SEV_COLORS[f.severity] : rgb(0, 0, 0);
          page.drawText(lines[j], { x: x + 2, y: rowY - (j * 11) - 2, size: 9, font, color });
        }
        x += colWidths[i];
      }

      const lineY = rowY + 2;
      page.drawLine({ start: { x: MARGIN, y: lineY }, end: { x: PAGE_W - MARGIN, y: lineY }, thickness: 0.5, color: rgb(0.85, 0.85, 0.85) });
      y = rowY - (maxLines * 11) - 4;
    }
  }

  // ─── Page: NIST 800-161 Compliance Matrix ───────────────────────────
  page = doc.addPage([PAGE_W, PAGE_H]);
  y = PAGE_H - MARGIN;
  y = drawPageHeader(page, boldFont, 'NIST SP 800-161 Compliance Summary', y);
  y -= 6;

  const nistColWidths = [70, CONTENT_W - 180, 110];
  const nistHeaders = ['Control', 'Control Title', 'Status'];
  x = MARGIN;
  for (let i = 0; i < nistHeaders.length; i++) {
    page.drawText(nistHeaders[i], { x: x + 2, y, size: 10, font: boldFont, color: rgb(0, 0, 0) });
    x += nistColWidths[i];
  }
  y -= 16;

  const atkMap = {};
  for (const s of scans) {
    for (const f of (s.findings || [])) {
      const key = f.atk_id || f.id;
      if (!atkMap[key]) atkMap[key] = [];
      atkMap[key].push(f);
    }
  }

  for (const [atkId, { control, title }] of Object.entries(NIST_SR_MAP)) {
    if (y < MARGIN + 20) {
      page = doc.addPage([PAGE_W, PAGE_H]);
      y = PAGE_H - MARGIN;
    }

    const count = (atkMap[atkId] || []).length;
    const status = count > 0 ? `${count} finding(s)` : 'Pass';
    const statusColor = count > 0 ? rgb(0.8, 0.2, 0.2) : rgb(0.2, 0.6, 0.2);

    const rowData = [control, title, status];
    const rowWidths = nistColWidths;

    x = MARGIN;
    for (let i = 0; i < rowData.length; i++) {
      const color = i === 2 ? statusColor : rgb(0, 0, 0);
      const fnt = i === 0 ? boldFont : font;
      page.drawText(rowData[i], { x: x + 2, y: y - 2, size: 9, font: fnt, color });
      x += rowWidths[i];
    }

    page.drawLine({ start: { x: MARGIN, y: y + 4 }, end: { x: PAGE_W - MARGIN, y: y + 4 }, thickness: 0.5, color: rgb(0.85, 0.85, 0.85) });
    y -= 18;
  }

  // Footer
  const pages = doc.getPages();
  for (const p of pages) {
    const { width } = p.getSize();
    p.drawText(`npm-scan v${version} | Apache-2.0 + Commons Clause`, {
      x: MARGIN, y: 20, size: 8, font, color: rgb(0.6, 0.6, 0.6),
    });
  }

  return doc.save();
}
