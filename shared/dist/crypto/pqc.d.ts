export interface KemKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}
export interface DsaKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}
export declare function generateKeyPairKEM(): KemKeyPair;
export declare function generateKeyPairDSA(): DsaKeyPair;
export declare function wrapKeyWithKEM(recipientKemPublicKey: Uint8Array, secretKeyToWrap: Uint8Array): Promise<{
    kemCiphertext: Uint8Array;
    wrappedKey: Uint8Array;
    iv: Uint8Array;
}>;
export declare function unwrapKeyWithKEM(recipientKemSecretKey: Uint8Array, kemCiphertext: Uint8Array, wrappedKey: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
export declare function signWithDSA(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
export declare function verifyWithDSA(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
