import { dct8x8, idct8x8 } from './dct.js';
import { appendCrc16, verifyAndStripCrc16 } from './crc.js';
import { sha256Bytes, hexToBytes, bytesToHex } from '../crypto/hash.js';
// Mid-frequency coefficient pair indices in 8x8 row-major layout
// (row 3, col 2) -> index 26
// (row 2, col 3) -> index 19
const IDX_3_2 = 3 * 8 + 2; // 26
const IDX_2_3 = 2 * 8 + 3; // 19
// Embedding margin T: guarantees robustness against JPEG down to Q55 while maintaining PSNR >= 40 dB
export const DEFAULT_MARGIN_T = 22.0;
/**
 * Deterministic PRNG seeded by 32-byte key (Mulberry32).
 */
function createPrng(seedBytes) {
    let state = ((seedBytes[0] | (seedBytes[1] << 8) | (seedBytes[2] << 16) | (seedBytes[3] << 24)) >>> 0) ^
        0xdeadbeef;
    return function next() {
        state = (state + 0x6d2b79f5) | 0;
        let t = Math.imul(state ^ (state >>> 15), 1 | state);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}
/**
 * Generates a pseudo-random permutation of block indices [0..numBlocks-1]
 */
function getBlockPermutation(numBlocks, docKey) {
    const seed = typeof docKey === 'string' ? new TextEncoder().encode(docKey) : docKey;
    const hash = sha256Bytes(seed);
    const prng = createPrng(hash);
    const perm = new Uint32Array(numBlocks);
    for (let i = 0; i < numBlocks; i++) {
        perm[i] = i;
    }
    // Fisher-Yates shuffle
    for (let i = numBlocks - 1; i > 0; i--) {
        const j = Math.floor(prng() * (i + 1));
        const tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
    return perm;
}
/**
 * Applies uniform #FAFAFA (RGB: 250, 250, 250) paper tint to provide headroom
 * in flat white regions against clipping saturation.
 */
export function applyPaperTint(rgba, width, height) {
    const len = width * height * 4;
    for (let i = 0; i < len; i += 4) {
        if (rgba[i] > 250)
            rgba[i] = 250;
        if (rgba[i + 1] > 250)
            rgba[i + 1] = 250;
        if (rgba[i + 2] > 250)
            rgba[i + 2] = 250;
    }
}
/**
 * Embeds a 96-bit watermark_id (12 bytes) + CRC16 into an RGBA image buffer.
 * Pure and pixel-level: testable in Node and runnable on browser canvas.
 */
export function embedWatermark(rgba, width, height, watermarkId, docKey, marginT = DEFAULT_MARGIN_T) {
    applyPaperTint(rgba, width, height);
    const rawPayload = typeof watermarkId === 'string' ? hexToBytes(watermarkId) : watermarkId;
    if (rawPayload.length !== 12) {
        throw new Error('Watermark ID must be exactly 12 bytes (96 bits)');
    }
    // Append 16-bit CRC -> 14 bytes = 112 bits
    const payloadWithCrc = appendCrc16(rawPayload);
    const totalBits = payloadWithCrc.length * 8; // 112
    // Convert payload to array of bit values (0 or 1)
    const bitArray = new Uint8Array(totalBits);
    for (let i = 0; i < payloadWithCrc.length; i++) {
        const byte = payloadWithCrc[i];
        for (let b = 0; b < 8; b++) {
            bitArray[i * 8 + b] = (byte >> (7 - b)) & 1;
        }
    }
    const blocksX = Math.floor(width / 8);
    const blocksY = Math.floor(height / 8);
    const totalBlocks = blocksX * blocksY;
    if (totalBlocks < totalBits) {
        throw new Error(`Image is too small for watermark. Needs at least ${totalBits} blocks (approx ${Math.ceil(Math.sqrt(totalBits * 64))}px)`);
    }
    const perm = getBlockPermutation(totalBlocks, docKey);
    const blockPixelsIn = new Float64Array(64);
    const blockDct = new Float64Array(64);
    const blockPixelsOut = new Float64Array(64);
    for (let k = 0; k < totalBlocks; k++) {
        const blockIdx = perm[k];
        const bitToEmbed = bitArray[k % totalBits];
        const bx = blockIdx % blocksX;
        const by = Math.floor(blockIdx / blocksX);
        const startX = bx * 8;
        const startY = by * 8;
        // Extract luminance Y for the 8x8 block
        for (let y = 0; y < 8; y++) {
            for (let x = 0; x < 8; x++) {
                const pixelIdx = ((startY + y) * width + (startX + x)) * 4;
                const r = rgba[pixelIdx];
                const g = rgba[pixelIdx + 1];
                const b = rgba[pixelIdx + 2];
                // Rec 601 Luminance
                const lum = 0.299 * r + 0.587 * g + 0.114 * b;
                blockPixelsIn[y * 8 + x] = lum;
            }
        }
        // Forward 8x8 DCT
        dct8x8(blockPixelsIn, blockDct);
        // Differential embedding on (3,2) vs (2,3)
        const c1 = blockDct[IDX_3_2];
        const c2 = blockDct[IDX_2_3];
        const diff = c1 - c2;
        if (bitToEmbed === 1) {
            if (diff < marginT) {
                const adjustment = (marginT - diff) / 2 + 0.05;
                blockDct[IDX_3_2] += adjustment;
                blockDct[IDX_2_3] -= adjustment;
            }
        }
        else {
            if (-diff < marginT) {
                const adjustment = (marginT + diff) / 2 + 0.05;
                blockDct[IDX_3_2] -= adjustment;
                blockDct[IDX_2_3] += adjustment;
            }
        }
        // Inverse 8x8 DCT
        idct8x8(blockDct, blockPixelsOut);
        // Apply spatial luminance delta to RGB channels
        for (let y = 0; y < 8; y++) {
            for (let x = 0; x < 8; x++) {
                const pixelIdx = ((startY + y) * width + (startX + x)) * 4;
                const origY = blockPixelsIn[y * 8 + x];
                const newY = blockPixelsOut[y * 8 + x];
                const delta = Math.round(newY - origY);
                rgba[pixelIdx] = Math.max(0, Math.min(255, rgba[pixelIdx] + delta));
                rgba[pixelIdx + 1] = Math.max(0, Math.min(255, rgba[pixelIdx + 1] + delta));
                rgba[pixelIdx + 2] = Math.max(0, Math.min(255, rgba[pixelIdx + 2] + delta));
            }
        }
    }
}
/**
 * Normalizes an image buffer to canonical dimensions using high-quality bilinear interpolation.
 * If canonical dimensions are derived from PDF page size in points (at 72 DPI):
 * canonicalWidth = Math.round(pointWidth * 150 / 72)
 * canonicalHeight = Math.round(pointHeight * 150 / 72)
 */
export function normalizeToCanonicalGrid(srcRgba, sw, sh, canonicalWidth, canonicalHeight) {
    if (sw === canonicalWidth && sh === canonicalHeight) {
        return srcRgba instanceof Uint8Array ? srcRgba : new Uint8Array(srcRgba);
    }
    const dstRgba = new Uint8Array(canonicalWidth * canonicalHeight * 4);
    const xRatio = sw / canonicalWidth;
    const yRatio = sh / canonicalHeight;
    for (let dy = 0; dy < canonicalHeight; dy++) {
        const sy = dy * yRatio;
        const y0 = Math.floor(sy);
        const y1 = Math.min(sh - 1, y0 + 1);
        const fy = sy - y0;
        for (let dx = 0; dx < canonicalWidth; dx++) {
            const sx = dx * xRatio;
            const x0 = Math.floor(sx);
            const x1 = Math.min(sw - 1, x0 + 1);
            const fx = sx - x0;
            const dstIdx = (dy * canonicalWidth + dx) * 4;
            for (let c = 0; c < 3; c++) {
                const c00 = srcRgba[(y0 * sw + x0) * 4 + c];
                const c10 = srcRgba[(y0 * sw + x1) * 4 + c];
                const c01 = srcRgba[(y1 * sw + x0) * 4 + c];
                const c11 = srcRgba[(y1 * sw + x1) * 4 + c];
                const top = c00 * (1 - fx) + c10 * fx;
                const bot = c01 * (1 - fx) + c11 * fx;
                dstRgba[dstIdx + c] = Math.round(top * (1 - fy) + bot * fy);
            }
            dstRgba[dstIdx + 3] = 255;
        }
    }
    return dstRgba;
}
/**
 * Extracts embedded watermark payload using majority voting across repeated 8x8 blocks.
 * If canonicalGrid is provided, the image is normalized to the canonical 150 DPI grid before extraction.
 */
export function extractWatermark(rgba, width, height, docKey, canonicalGrid) {
    let wasNormalized = false;
    if (canonicalGrid) {
        let targetW = width;
        let targetH = height;
        if ('pagePointsWidth' in canonicalGrid && 'pagePointsHeight' in canonicalGrid) {
            targetW = Math.round((canonicalGrid.pagePointsWidth * 150) / 72);
            targetH = Math.round((canonicalGrid.pagePointsHeight * 150) / 72);
        }
        else if ('width' in canonicalGrid && 'height' in canonicalGrid) {
            targetW = canonicalGrid.width;
            targetH = canonicalGrid.height;
        }
        if (width !== targetW || height !== targetH) {
            rgba = normalizeToCanonicalGrid(rgba, width, height, targetW, targetH);
            width = targetW;
            height = targetH;
            wasNormalized = true;
        }
    }
    const totalBits = 112; // 96 bits payload + 16 bits CRC
    const blocksX = Math.floor(width / 8);
    const blocksY = Math.floor(height / 8);
    const totalBlocks = blocksX * blocksY;
    if (totalBlocks < totalBits) {
        return {
            watermarkId: null,
            watermarkBytes: null,
            crcValid: false,
            totalBlocks,
            repetitions: 0,
            normalized: wasNormalized,
        };
    }
    const perm = getBlockPermutation(totalBlocks, docKey);
    const votes0 = new Float64Array(totalBits);
    const votes1 = new Float64Array(totalBits);
    const blockPixels = new Float64Array(64);
    const blockDct = new Float64Array(64);
    for (let k = 0; k < totalBlocks; k++) {
        const blockIdx = perm[k];
        const bitIdx = k % totalBits;
        const bx = blockIdx % blocksX;
        const by = Math.floor(blockIdx / blocksX);
        const startX = bx * 8;
        const startY = by * 8;
        for (let y = 0; y < 8; y++) {
            for (let x = 0; x < 8; x++) {
                const pixelIdx = ((startY + y) * width + (startX + x)) * 4;
                const r = rgba[pixelIdx];
                const g = rgba[pixelIdx + 1];
                const b = rgba[pixelIdx + 2];
                blockPixels[y * 8 + x] = 0.299 * r + 0.587 * g + 0.114 * b;
            }
        }
        dct8x8(blockPixels, blockDct);
        const c1 = blockDct[IDX_3_2];
        const c2 = blockDct[IDX_2_3];
        const diff = c1 - c2;
        // Soft weighted voting based on difference magnitude
        if (diff > 0) {
            votes1[bitIdx] += Math.min(diff, 50);
        }
        else {
            votes0[bitIdx] += Math.min(-diff, 50);
        }
    }
    // Reconstruct bytes
    const extractedBytes = new Uint8Array(14);
    for (let b = 0; b < 14; b++) {
        let byteVal = 0;
        for (let bit = 0; bit < 8; bit++) {
            const bitIndex = b * 8 + bit;
            const bitVal = votes1[bitIndex] >= votes0[bitIndex] ? 1 : 0;
            byteVal = (byteVal << 1) | bitVal;
        }
        extractedBytes[b] = byteVal;
    }
    const { valid, payload } = verifyAndStripCrc16(extractedBytes);
    return {
        watermarkId: valid ? bytesToHex(payload) : null,
        watermarkBytes: valid ? payload : null,
        crcValid: valid,
        totalBlocks,
        repetitions: Math.floor(totalBlocks / totalBits),
    };
}
/**
 * Calculates PSNR (Peak Signal to Noise Ratio) between two images.
 */
export function calculatePsnr(originalRgba, modifiedRgba, width, height) {
    let sumSquaredDiff = 0;
    const pixelCount = width * height;
    for (let i = 0; i < pixelCount * 4; i += 4) {
        const dr = originalRgba[i] - modifiedRgba[i];
        const dg = originalRgba[i + 1] - modifiedRgba[i + 1];
        const db = originalRgba[i + 2] - modifiedRgba[i + 2];
        sumSquaredDiff += dr * dr + dg * dg + db * db;
    }
    const mse = sumSquaredDiff / (pixelCount * 3);
    if (mse === 0)
        return 999;
    return 10 * Math.log10((255 * 255) / mse);
}
/**
 * Calculates normalized mean absolute pixel difference.
 */
export function calculateMeanAbsDiff(img1, img2, width, height) {
    let sumAbsDiff = 0;
    const pixelCount = width * height;
    for (let i = 0; i < pixelCount * 4; i += 4) {
        sumAbsDiff += Math.abs(img1[i] - img2[i]);
        sumAbsDiff += Math.abs(img1[i + 1] - img2[i + 1]);
        sumAbsDiff += Math.abs(img1[i + 2] - img2[i + 2]);
    }
    return sumAbsDiff / (pixelCount * 3 * 255);
}
