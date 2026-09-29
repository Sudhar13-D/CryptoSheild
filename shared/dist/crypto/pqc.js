import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { deriveKeyHkdf } from './hash.js';
import { encryptAesGcm, decryptAesGcm } from './symmetric.js';
export function generateKeyPairKEM() {
    const kp = ml_kem768.keygen();
    return {
        publicKey: kp.publicKey,
        secretKey: kp.secretKey,
    };
}
export function generateKeyPairDSA() {
    const kp = ml_dsa65.keygen();
    return {
        publicKey: kp.publicKey,
        secretKey: kp.secretKey,
    };
}
const KEM_SALT = 'CRYPTOSHIELD-KEM-SALT-V1';
const KEM_INFO = 'AES-GCM-WRAP-KEY';
export async function wrapKeyWithKEM(recipientKemPublicKey, secretKeyToWrap) {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipientKemPublicKey);
    const wrappingKey = deriveKeyHkdf(sharedSecret, KEM_SALT, KEM_INFO, 32);
    const { ciphertext: wrappedKey, iv } = await encryptAesGcm(wrappingKey, secretKeyToWrap);
    return {
        kemCiphertext: cipherText,
        wrappedKey,
        iv,
    };
}
export async function unwrapKeyWithKEM(recipientKemSecretKey, kemCiphertext, wrappedKey, iv) {
    const sharedSecret = ml_kem768.decapsulate(kemCiphertext, recipientKemSecretKey);
    const wrappingKey = deriveKeyHkdf(sharedSecret, KEM_SALT, KEM_INFO, 32);
    return await decryptAesGcm(wrappingKey, wrappedKey, iv);
}
export function signWithDSA(message, secretKey) {
    return ml_dsa65.sign(message, secretKey);
}
export function verifyWithDSA(signature, message, publicKey) {
    try {
        return ml_dsa65.verify(signature, message, publicKey);
    }
    catch {
        return false;
    }
}
