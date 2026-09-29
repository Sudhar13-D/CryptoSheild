export declare function bytesToHex(bytes: Uint8Array): string;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function sha3_256Bytes(data: Uint8Array | string): Uint8Array;
export declare function sha3_256Hex(data: Uint8Array | string): string;
export declare function sha256Bytes(data: Uint8Array | string): Uint8Array;
export declare function sha256Hex(data: Uint8Array | string): string;
export declare function deriveKeyHkdf(ikm: Uint8Array, salt: Uint8Array | string, info: Uint8Array | string, length?: number): Uint8Array;
