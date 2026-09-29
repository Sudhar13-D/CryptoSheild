export declare function getRandomBytes(length: number): Uint8Array;
export declare function splitKey(key: Uint8Array): {
    k1: Uint8Array;
    k2: Uint8Array;
};
export declare function combineKey(k1: Uint8Array, k2: Uint8Array): Uint8Array;
export declare function encryptAesGcm(keyBytes: Uint8Array, plaintext: Uint8Array, iv?: Uint8Array, additionalData?: Uint8Array): Promise<{
    ciphertext: Uint8Array;
    iv: Uint8Array;
}>;
export declare function decryptAesGcm(keyBytes: Uint8Array, ciphertext: Uint8Array, iv: Uint8Array, additionalData?: Uint8Array): Promise<Uint8Array>;
/**
 * PBKDF2-SHA256 Key derivation for encrypted key storage.
 * Standard parameter: >= 600,000 iterations for secure password hashing.
 */
export declare function deriveVaultKey(password: string, salt: Uint8Array, iterations?: number): Promise<CryptoKey>;
export declare function encryptVault(plaintext: Uint8Array, password: string, iterations?: number): Promise<{
    salt: Uint8Array;
    iv: Uint8Array;
    ciphertext: Uint8Array;
    iterations: number;
}>;
export declare function decryptVault(vault: {
    salt: Uint8Array;
    iv: Uint8Array;
    ciphertext: Uint8Array;
    iterations?: number;
}, password: string): Promise<Uint8Array>;
