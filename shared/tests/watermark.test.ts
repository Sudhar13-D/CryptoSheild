import { describe, it, expect } from 'vitest';
import jpeg from 'jpeg-js';
import {
  embedWatermark,
  extractWatermark,
  calculatePsnr,
  calculateMeanAbsDiff,
  hexToBytes,
  bytesToHex,
} from '../src/index.js';

function createSyntheticPage(width: number, height: number): Uint8Array {
  const rgba = new Uint8Array(width * height * 4);
  // Fill with off-white document paper #FAFAFA (RGB: 250, 250, 250)
  for (let i = 0; i < rgba.length; i += 4) {
    rgba[i] = 250;
    rgba[i + 1] = 250;
    rgba[i + 2] = 250;
    rgba[i + 3] = 255;
  }

  // Draw some simulated text lines (dark grey blocks)
  for (let y = 40; y < height - 40; y += 24) {
    for (let x = 40; x < width - 60; x++) {
      // Simulate characters and spaces
      if ((x % 35) > 8) {
        for (let dy = 0; dy < 12; dy++) {
          const idx = ((y + dy) * width + x) * 4;
          rgba[idx] = 30;
          rgba[idx + 1] = 30;
          rgba[idx + 2] = 35;
        }
      }
    }
  }

  return rgba;
}

describe('Forensic Watermark Channel 1 Engine', () => {
  const width = 512;
  const height = 512;
  const docKey = 'DOC-KEY-TEST-FORENSIC-2026';

  it('Watermark exact extraction for 3 distinct payloads', () => {
    const payloads = [
      '0102030405060708090a0b0c',
      'fedcba987654321011223344',
      'a1b2c3d4e5f6a7b8c9d0e1f2',
    ];

    for (const payloadHex of payloads) {
      const pageRgba = createSyntheticPage(width, height);
      embedWatermark(pageRgba, width, height, payloadHex, docKey);

      const result = extractWatermark(pageRgba, width, height, docKey);
      expect(result.crcValid).toBe(true);
      expect(result.watermarkId?.toLowerCase()).toBe(payloadHex.toLowerCase());
    }
  });

  it('Watermark survives JPEG compression at quality 70', () => {
    const payloadHex = 'deadbeefcafebabeface1234';
    const pageRgba = createSyntheticPage(width, height);
    embedWatermark(pageRgba, width, height, payloadHex, docKey);

    // Compress with JPEG Q=70
    const rawImageData = {
      data: Buffer.from(pageRgba),
      width,
      height,
    };
    const jpegBuffer = jpeg.encode(rawImageData, 70);

    // Decode compressed JPEG
    const decoded = jpeg.decode(jpegBuffer.data, { useTArray: true });
    const decodedRgba = new Uint8Array(decoded.data);

    // Extract watermark from compressed image
    const result = extractWatermark(decodedRgba, width, height, docKey);
    expect(result.crcValid).toBe(true);
    expect(result.watermarkId?.toLowerCase()).toBe(payloadHex.toLowerCase());
  });

  it('Watermark survives additive Gaussian noise', () => {
    const payloadHex = '11223344556677889900aabb';
    const pageRgba = createSyntheticPage(width, height);
    embedWatermark(pageRgba, width, height, payloadHex, docKey);

    // Add mild Gaussian-like noise (stddev ~ 2.5)
    for (let i = 0; i < pageRgba.length; i += 4) {
      const noise = Math.round((Math.random() - 0.5) * 5);
      pageRgba[i] = Math.max(0, Math.min(255, pageRgba[i] + noise));
      pageRgba[i + 1] = Math.max(0, Math.min(255, pageRgba[i + 1] + noise));
      pageRgba[i + 2] = Math.max(0, Math.min(255, pageRgba[i + 2] + noise));
    }

    const result = extractWatermark(pageRgba, width, height, docKey);
    expect(result.crcValid).toBe(true);
    expect(result.watermarkId?.toLowerCase()).toBe(payloadHex.toLowerCase());
  });

  it('Two watermarked copies of the same page have mean abs pixel diff < 2/255 and PSNR >= 38 dB while payloads differ', () => {
    const original = createSyntheticPage(width, height);

    const payloadA = 'aaaaaaaaaaaabbbbbbbbbbbb';
    const payloadB = 'ccccccccccccdddddddddddd';

    const copyA = createSyntheticPage(width, height);
    const copyB = createSyntheticPage(width, height);

    embedWatermark(copyA, width, height, payloadA, docKey);
    embedWatermark(copyB, width, height, payloadB, docKey);

    // Verify both payloads extract correctly and differ
    const resA = extractWatermark(copyA, width, height, docKey);
    const resB = extractWatermark(copyB, width, height, docKey);
    expect(resA.watermarkId).toBe(payloadA);
    expect(resB.watermarkId).toBe(payloadB);
    expect(resA.watermarkId).not.toBe(resB.watermarkId);

    // PSNR relative to original must be >= 38 dB
    const psnrA = calculatePsnr(original, copyA, width, height);
    const psnrB = calculatePsnr(original, copyB, width, height);
    expect(psnrA).toBeGreaterThanOrEqual(38.0);
    expect(psnrB).toBeGreaterThanOrEqual(38.0);

    // Mean absolute pixel difference between copyA and copyB must be < 2/255
    const meanAbsDiff = calculateMeanAbsDiff(copyA, copyB, width, height);
    const threshold = 2.0 / 255.0; // approx 0.00784
    expect(meanAbsDiff).toBeLessThan(threshold);
  });
});
