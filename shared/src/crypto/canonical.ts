/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
 * Produces deterministic UTF-8 byte representation of JSON structures.
 */
export function canonicalJsonStringify(obj: unknown): string {
  if (obj === null || obj === undefined) {
    return 'null';
  }
  if (typeof obj === 'boolean' || typeof obj === 'number') {
    return JSON.stringify(obj);
  }
  if (typeof obj === 'string') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    const elements = obj.map((item) => canonicalJsonStringify(item));
    return '[' + elements.join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    const keyValues = keys.map((key) => {
      const val = (obj as Record<string, unknown>)[key];
      return JSON.stringify(key) + ':' + canonicalJsonStringify(val);
    });
    return '{' + keyValues.join(',') + '}';
  }
  return JSON.stringify(obj);
}

export function canonicalJsonBytes(obj: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJsonStringify(obj));
}
