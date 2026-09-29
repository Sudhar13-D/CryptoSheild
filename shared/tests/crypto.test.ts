import { describe, it, expect } from 'vitest';
import {
  canonicalJsonStringify,
  canonicalJsonBytes,
  generateKeyPairKEM,
  generateKeyPairDSA,
  wrapKeyWithKEM,
  unwrapKeyWithKEM,
  signWithDSA,
  verifyWithDSA,
  encryptAesGcm,
  decryptAesGcm,
  splitKey,
  combineKey,
  encryptVault,
  decryptVault,
  getRandomBytes,
  sha3_256Hex,
} from '../src/index.js';

describe('Cryptographic Core Tests', () => {
  it('RFC 8785 Canonical JSON produces deterministic output regardless of key order', () => {
    const objA = { z: 1, a: 'hello', m: { b: 2, a: 1 } };
    const objB = { m: { a: 1, b: 2 }, a: 'hello', z: 1 };

    const strA = canonicalJsonStringify(objA);
    const strB = canonicalJsonStringify(objB);

    expect(strA).toBe(strB);
    expect(strA).toBe('{"a":"hello","m":{"a":1,"b":2},"z":1}');

    const bytesA = canonicalJsonBytes(objA);
    const bytesB = canonicalJsonBytes(objB);
    expect(bytesA).toEqual(bytesB);
  });

  it('ML-KEM-768 key wrap and unwrap round-trip succeeds', async () => {
    const recipientKem = generateKeyPairKEM();
    const fileKeyPart = getRandomBytes(32); // 32-byte key (e.g. K1 or K2)

    const wrapped = await wrapKeyWithKEM(recipientKem.publicKey, fileKeyPart);
    expect(wrapped.kemCiphertext.length).toBeGreaterThan(0);
    expect(wrapped.wrappedKey.length).toBeGreaterThan(0);

    const unwrapped = await unwrapKeyWithKEM(
      recipientKem.secretKey,
      wrapped.kemCiphertext,
      wrapped.wrappedKey,
      wrapped.iv
    );

    expect(unwrapped).toEqual(fileKeyPart);
  });

  it('ML-DSA-65 signs and verifies message and rejects tampered data', () => {
    const signer = generateKeyPairDSA();
    const msg = new TextEncoder().encode('Decryption Provenance Record #42');

    const signature = signWithDSA(msg, signer.secretKey);
    const isValid = verifyWithDSA(signature, msg, signer.publicKey);
    expect(isValid).toBe(true);

    const tampered = new TextEncoder().encode('Decryption Provenance Record #43');
    const isTamperedValid = verifyWithDSA(signature, tampered, signer.publicKey);
    expect(isTamperedValid).toBe(false);
  });

  it('AES-256-GCM symmetric encryption and decryption', async () => {
    const key = getRandomBytes(32);
    const plaintext = new TextEncoder().encode('Classified PDF plaintext stream');

    const { ciphertext, iv } = await encryptAesGcm(key, plaintext);
    const decrypted = await decryptAesGcm(key, ciphertext, iv);

    expect(new TextDecoder().decode(decrypted)).toBe('Classified PDF plaintext stream');
  });

  it('Secret sharing K = K1 XOR K2 correctly splits and reconstructs 32-byte key', () => {
    const K = getRandomBytes(32);
    const { k1, k2 } = splitKey(K);

    expect(k1.length).toBe(32);
    expect(k2.length).toBe(32);
    expect(k1).not.toEqual(K);
    expect(k2).not.toEqual(K);

    const reconstructed = combineKey(k1, k2);
    expect(reconstructed).toEqual(K);
  });

  it('Local Vault encryption with PBKDF2-SHA256 (>=600,000 iterations)', async () => {
    const secretKeys = new TextEncoder().encode('ML-KEM-SECRET-KEY-RAW-BYTES');
    const password = 'StrongMasterPassword!2026';

    const vault = await encryptVault(secretKeys, password, 600000);
    expect(vault.iterations).toBe(600000);

    const decrypted = await decryptVault(vault, password);
    expect(new TextDecoder().decode(decrypted)).toBe('ML-KEM-SECRET-KEY-RAW-BYTES');

    // Wrong password should fail decryption
    await expect(decryptVault(vault, 'WrongPassword')).rejects.toThrow();
  });
});
