export interface MerkleProofStep {
    position: 'left' | 'right';
    hash: string;
}
/**
 * Computes the SHA3-256 Merkle root of an array of leaf hashes.
 */
export declare function computeMerkleRoot(leaves: string[]): string;
/**
 * Generates a Merkle inclusion proof for a leaf at leafIndex.
 */
export declare function generateMerkleProof(leaves: string[], leafIndex: number): string[];
/**
 * Verifies a Merkle inclusion proof against a known root.
 */
export declare function verifyMerkleProof(leafHash: string, proof: string[], merkleRoot: string): boolean;
