export declare const DEFAULT_MARGIN_T = 22;
/**
 * Applies uniform #FAFAFA (RGB: 250, 250, 250) paper tint to provide headroom
 * in flat white regions against clipping saturation.
 */
export declare function applyPaperTint(rgba: Uint8ClampedArray | Uint8Array, width: number, height: number): void;
/**
 * Embeds a 96-bit watermark_id (12 bytes) + CRC16 into an RGBA image buffer.
 * Pure and pixel-level: testable in Node and runnable on browser canvas.
 */
export declare function embedWatermark(rgba: Uint8ClampedArray | Uint8Array, width: number, height: number, watermarkId: Uint8Array | string, docKey: Uint8Array | string, marginT?: number): void;
export interface WatermarkExtractionResult {
    watermarkId: string | null;
    watermarkBytes: Uint8Array | null;
    crcValid: boolean;
    bitErrorRateEstimate?: number;
    totalBlocks: number;
    repetitions: number;
    normalized?: boolean;
}
export type CanonicalGridSpec = {
    width: number;
    height: number;
} | {
    pagePointsWidth: number;
    pagePointsHeight: number;
};
/**
 * Normalizes an image buffer to canonical dimensions using high-quality bilinear interpolation.
 * If canonical dimensions are derived from PDF page size in points (at 72 DPI):
 * canonicalWidth = Math.round(pointWidth * 150 / 72)
 * canonicalHeight = Math.round(pointHeight * 150 / 72)
 */
export declare function normalizeToCanonicalGrid(srcRgba: Uint8ClampedArray | Uint8Array, sw: number, sh: number, canonicalWidth: number, canonicalHeight: number): Uint8Array;
/**
 * Extracts embedded watermark payload using majority voting across repeated 8x8 blocks.
 * If canonicalGrid is provided, the image is normalized to the canonical 150 DPI grid before extraction.
 */
export declare function extractWatermark(rgba: Uint8ClampedArray | Uint8Array, width: number, height: number, docKey: Uint8Array | string, canonicalGrid?: CanonicalGridSpec): WatermarkExtractionResult;
/**
 * Calculates PSNR (Peak Signal to Noise Ratio) between two images.
 */
export declare function calculatePsnr(originalRgba: Uint8ClampedArray | Uint8Array, modifiedRgba: Uint8ClampedArray | Uint8Array, width: number, height: number): number;
/**
 * Calculates normalized mean absolute pixel difference.
 */
export declare function calculateMeanAbsDiff(img1: Uint8ClampedArray | Uint8Array, img2: Uint8ClampedArray | Uint8Array, width: number, height: number): number;
