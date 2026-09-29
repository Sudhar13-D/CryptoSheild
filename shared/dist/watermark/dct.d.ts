/**
 * Orthonormal 8x8 2D-DCT-II and IDCT-II using precomputed transform matrices.
 */
/**
 * Computes 2D-DCT of an 8x8 block: F = C * f * Ct
 */
export declare function dct8x8(input: Float64Array, output: Float64Array): void;
/**
 * Computes 2D-IDCT of an 8x8 block: f = Ct * F * C
 */
export declare function idct8x8(input: Float64Array, output: Float64Array): void;
