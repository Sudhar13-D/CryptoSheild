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
export declare function embedChannel2(pdfBytes: Uint8Array, watermarkIdHex: string): Promise<Uint8Array>;
/**
 * Extracts Channel 2 metadata and invisible text from PDF bytes.
 */
export declare function extractChannel2(pdfBytes: Uint8Array): Promise<Channel2ExtractionResult>;
