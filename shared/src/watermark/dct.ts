/**
 * Orthonormal 8x8 2D-DCT-II and IDCT-II using precomputed transform matrices.
 */

const N = 8;
const C: Float64Array = new Float64Array(N * N);
const Ct: Float64Array = new Float64Array(N * N);

// Precompute orthonormal DCT basis matrix C and its transpose Ct
for (let u = 0; u < N; u++) {
  const alpha = u === 0 ? 1 / Math.sqrt(8) : Math.sqrt(2 / 8);
  for (let x = 0; x < N; x++) {
    const val = alpha * Math.cos(((2 * x + 1) * u * Math.PI) / (2 * N));
    C[u * N + x] = val;
    Ct[x * N + u] = val;
  }
}

// Reusable scratch buffers for 8x8 blocks to avoid GC churn
const scratchTemp = new Float64Array(N * N);

/**
 * Computes 2D-DCT of an 8x8 block: F = C * f * Ct
 */
export function dct8x8(input: Float64Array, output: Float64Array): void {
  // temp = C * input
  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {
      let sum = 0;
      for (let k = 0; k < N; k++) {
        sum += C[i * N + k] * input[k * N + j];
      }
      scratchTemp[i * N + j] = sum;
    }
  }

  // output = temp * Ct
  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {
      let sum = 0;
      for (let k = 0; k < N; k++) {
        sum += scratchTemp[i * N + k] * Ct[k * N + j];
      }
      output[i * N + j] = sum;
    }
  }
}

/**
 * Computes 2D-IDCT of an 8x8 block: f = Ct * F * C
 */
export function idct8x8(input: Float64Array, output: Float64Array): void {
  // temp = Ct * input
  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {
      let sum = 0;
      for (let k = 0; k < N; k++) {
        sum += Ct[i * N + k] * input[k * N + j];
      }
      scratchTemp[i * N + j] = sum;
    }
  }

  // output = temp * C
  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {
      let sum = 0;
      for (let k = 0; k < N; k++) {
        sum += scratchTemp[i * N + k] * C[k * N + j];
      }
      output[i * N + j] = sum;
    }
  }
}
