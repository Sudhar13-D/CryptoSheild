/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
 * Produces deterministic UTF-8 byte representation of JSON structures.
 */
export declare function canonicalJsonStringify(obj: unknown): string;
export declare function canonicalJsonBytes(obj: unknown): Uint8Array;
