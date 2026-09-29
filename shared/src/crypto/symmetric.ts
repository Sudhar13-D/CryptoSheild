export function getRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export function splitKey(key: Uint8Array): { k1: Uint8Array; k2: Uint8Array } {
  if (key.length !== 32) {
    throw new Error('Key must be exactly 32 bytes for AES-256');
  }
  const k1 = getRandomBytes(32);
  const k2 = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    k2[i] = key[i] ^ k1[i];
  }
  return { k1, k2 };
}

export function combineKey(k1: Uint8Array, k2: Uint8Array): Uint8Array {
  if (k1.length !== 32 || k2.length !== 32) {
    throw new Error('Keys must be 32 bytes each');
  }
  const k = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    k[i] = k1[i] ^ k2[i];
  }
  return k;
}

export async function encryptAesGcm(
  keyBytes: Uint8Array,
  plaintext: Uint8Array,
  iv?: Uint8Array,
  additionalData?: Uint8Array
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const nonce = iv || getRandomBytes(12);
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const algorithm: AesGcmParams = {
    name: 'AES-GCM',
    iv: nonce,
    tagLength: 128,
  };
  if (additionalData) {
    algorithm.additionalData = additionalData;
  }

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    algorithm,
    cryptoKey,
    plaintext
  );

  return {
    ciphertext: new Uint8Array(encryptedBuffer),
    iv: nonce,
  };
}

export async function decryptAesGcm(
  keyBytes: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const algorithm: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv,
    tagLength: 128,
  };
  if (additionalData) {
    algorithm.additionalData = additionalData;
  }

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    algorithm,
    cryptoKey,
    ciphertext
  );

  return new Uint8Array(decryptedBuffer);
}

/**
 * PBKDF2-SHA256 Key derivation for encrypted key storage.
 * Standard parameter: >= 600,000 iterations for secure password hashing.
 */
export async function deriveVaultKey(
  password: string,
  salt: Uint8Array,
  iterations: number = 600000
): Promise<CryptoKey> {
  const passwordKey = await globalThis.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return globalThis.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptVault(
  plaintext: Uint8Array,
  password: string,
  iterations: number = 600000
): Promise<{ salt: Uint8Array; iv: Uint8Array; ciphertext: Uint8Array; iterations: number }> {
  const salt = getRandomBytes(16);
  const iv = getRandomBytes(12);
  const derivedKey = await deriveVaultKey(password, salt, iterations);

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, tagLength: 128 },
    derivedKey,
    plaintext
  );

  return {
    salt,
    iv,
    ciphertext: new Uint8Array(encryptedBuffer),
    iterations,
  };
}

export async function decryptVault(
  vault: { salt: Uint8Array; iv: Uint8Array; ciphertext: Uint8Array; iterations?: number },
  password: string
): Promise<Uint8Array> {
  const iterations = vault.iterations || 600000;
  const derivedKey = await deriveVaultKey(password, vault.salt, iterations);

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: vault.iv, tagLength: 128 },
    derivedKey,
    vault.ciphertext
  );

  return new Uint8Array(decryptedBuffer);
}
