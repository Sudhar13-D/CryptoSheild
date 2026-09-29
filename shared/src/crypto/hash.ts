import { sha3_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('Hex string must have an even length');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

export function sha3_256Bytes(data: Uint8Array | string): Uint8Array {
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return sha3_256(input);
}

export function sha3_256Hex(data: Uint8Array | string): string {
  return bytesToHex(sha3_256Bytes(data));
}

export function sha256Bytes(data: Uint8Array | string): Uint8Array {
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return sha256(input);
}

export function sha256Hex(data: Uint8Array | string): string {
  return bytesToHex(sha256Bytes(data));
}

export function deriveKeyHkdf(
  ikm: Uint8Array,
  salt: Uint8Array | string,
  info: Uint8Array | string,
  length: number = 32
): Uint8Array {
  const saltBytes = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;
  return hkdf(sha256, ikm, saltBytes, infoBytes, length);
}
