import { describe, it, expect } from 'vitest';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

describe('PQC Smoke Tests', () => {
  it('ML-KEM-768: encapsulate and decapsulate round-trip generates identical shared secret', () => {
    const keyPair = ml_kem768.keygen();
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.secretKey).toBeDefined();

    const { cipherText, sharedSecret: senderSharedSecret } = ml_kem768.encapsulate(keyPair.publicKey);
    expect(cipherText.length).toBeGreaterThan(0);
    expect(senderSharedSecret.length).toBe(32);

    const recipientSharedSecret = ml_kem768.decapsulate(cipherText, keyPair.secretKey);
    expect(recipientSharedSecret).toEqual(senderSharedSecret);
  });

  it('ML-DSA-65: sign and verify round-trip succeeds and tampered message fails', () => {
    const keyPair = ml_dsa65.keygen();
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.secretKey).toBeDefined();

    const message = new TextEncoder().encode('Forensic Attribution Provenance Payload');
    const signature = ml_dsa65.sign(message, keyPair.secretKey);

    const isValid = ml_dsa65.verify(signature, message, keyPair.publicKey);
    expect(isValid).toBe(true);

    const tamperedMessage = new TextEncoder().encode('Forensic Attribution Tampered Payload');
    const isTamperedValid = ml_dsa65.verify(signature, tamperedMessage, keyPair.publicKey);
    expect(isTamperedValid).toBe(false);

    // Tampered signature should also fail
    const tamperedSig = new Uint8Array(signature);
    tamperedSig[0] ^= 0x01;
    const isTamperedSigValid = ml_dsa65.verify(tamperedSig, message, keyPair.publicKey);
    expect(isTamperedSigValid).toBe(false);
  });
});
