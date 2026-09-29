import { PDFDocument, rgb } from 'pdf-lib';

export interface Channel2ExtractionResult {
  watermarkId: string | null;
  foundInMetadata: boolean;
  foundInInvisibleText: boolean;
}

/**
 * Embeds Channel 2 (structural watermark) into a PDF document:
 * 1. Custom PDF Info/XMP entries (Subject, Producer, Creator)
 * 2. Invisible text token embedded on each page
 */
export async function embedChannel2(
  pdfBytes: Uint8Array,
  watermarkIdHex: string
): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.load(pdfBytes);

  // Set Info metadata
  pdfDoc.setSubject(`CRYPTOSHIELD-WM:${watermarkIdHex}`);
  pdfDoc.setProducer(`CRYPTOSHIELD-V1-${watermarkIdHex}`);
  pdfDoc.setCreator(`CRYPTOSHIELD-TOKEN:${watermarkIdHex}`);

  // Embed invisible text token on pages
  const pages = pdfDoc.getPages();
  const token = `CRYPTOSHIELD-ID:${watermarkIdHex}`;

  for (const page of pages) {
    page.drawText(token, {
      x: 10,
      y: 10,
      size: 1,
      color: rgb(0.98, 0.98, 0.98),
      opacity: 0.001,
    });
  }

  return await pdfDoc.save();
}

/**
 * Extracts Channel 2 metadata and invisible text from PDF bytes.
 */
export async function extractChannel2(pdfBytes: Uint8Array): Promise<Channel2ExtractionResult> {
  try {
    const pdfDoc = await PDFDocument.load(pdfBytes, { ignoreEncryption: true });

    let watermarkId: string | null = null;
    let foundInMetadata = false;
    let foundInInvisibleText = false;

    // Check Info fields
    const subject = pdfDoc.getSubject();
    const producer = pdfDoc.getProducer();
    const creator = pdfDoc.getCreator();

    const wmRegex = /(?:CRYPTOSHIELD-WM:|CRYPTOSHIELD-V1-|CRYPTOSHIELD-TOKEN:|CRYPTOSHIELD-ID:)?([0-9a-fA-F]{24})/;

    for (const field of [subject, producer, creator]) {
      if (field) {
        const match = field.match(wmRegex);
        if (match && match[1]) {
          watermarkId = match[1].toLowerCase();
          foundInMetadata = true;
          break;
        }
      }
    }

    // Inspect raw PDF content stream for invisible text token
    const textDecoder = new TextDecoder('latin1');
    const rawPdfString = textDecoder.decode(pdfBytes);
    const textMatch = rawPdfString.match(/CRYPTOSHIELD-ID:([0-9a-fA-F]{24})/);
    if (textMatch && textMatch[1]) {
      if (!watermarkId) watermarkId = textMatch[1].toLowerCase();
      foundInInvisibleText = true;
    }

    return {
      watermarkId,
      foundInMetadata,
      foundInInvisibleText,
    };
  } catch {
    return {
      watermarkId: null,
      foundInMetadata: false,
      foundInInvisibleText: false,
    };
  }
}
