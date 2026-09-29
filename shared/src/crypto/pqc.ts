import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { deriveKeyHkdf } from './hash.js';
import { encryptAesGcm, decryptAesGcm } from './symmetric.js';

export interface KemKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface DsaKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function generateKeyPairKEM(): KemKeyPair {
  const kp = ml_kem768.keygen();
  return {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
  };
}

export function generateKeyPairDSA(): DsaKeyPair {
  const kp = ml_dsa65.keygen();
  return {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
  };
}

const KEM_SALT = 'CRYPTOSHIELD-KEM-SALT-V1';
const KEM_INFO = 'AES-GCM-WRAP-KEY';

export async function wrapKeyWithKEM(
  recipientKemPublicKey: Uint8Array,
  secretKeyToWrap: Uint8Array
): Promise<{ kemCiphertext: Uint8Array; wrappedKey: Uint8Array; iv: Uint8Array }> {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipientKemPublicKey);
  const wrappingKey = deriveKeyHkdf(sharedSecret, KEM_SALT, KEM_INFO, 32);
  const { ciphertext: wrappedKey, iv } = await encryptAesGcm(wrappingKey, secretKeyToWrap);
  return {
    kemCiphertext: cipherText,
    wrappedKey,
    iv,
  };
}

export async function unwrapKeyWithKEM(
  recipientKemSecretKey: Uint8Array,
  kemCiphertext: Uint8Array,
  wrappedKey: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  const sharedSecret = ml_kem768.decapsulate(kemCiphertext, recipientKemSecretKey);
  const wrappingKey = deriveKeyHkdf(sharedSecret, KEM_SALT, KEM_INFO, 32);
  return await decryptAesGcm(wrappingKey, wrappedKey, iv);
}

export function signWithDSA(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, secretKey);
}

export function verifyWithDSA(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return ml_dsa65.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
