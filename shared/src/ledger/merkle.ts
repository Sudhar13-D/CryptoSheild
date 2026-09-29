import { sha3_256Hex } from '../crypto/hash.js';

export interface MerkleProofStep {
  position: 'left' | 'right';
  hash: string;
}

/**
 * Computes the SHA3-256 Merkle root of an array of leaf hashes.
 */
export function computeMerkleRoot(leaves: string[]): string {
  if (leaves.length === 0) {
    return sha3_256Hex('EMPTY_MERKLE_TREE');
  }

  let currentLevel = [...leaves];

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      if (i + 1 < currentLevel.length) {
        // Hash left + right
        nextLevel.push(sha3_256Hex(currentLevel[i] + currentLevel[i + 1]));
      } else {
        // Odd number of elements: duplicate last element
        nextLevel.push(sha3_256Hex(currentLevel[i] + currentLevel[i]));
      }
    }
    currentLevel = nextLevel;
  }

  return currentLevel[0];
}

/**
 * Generates a Merkle inclusion proof for a leaf at leafIndex.
 */
export function generateMerkleProof(leaves: string[], leafIndex: number): string[] {
  if (leafIndex < 0 || leafIndex >= leaves.length) {
    throw new Error('Leaf index out of bounds');
  }

  const proof: string[] = [];
  let currentLevel = [...leaves];
  let currentIndex = leafIndex;

  while (currentLevel.length > 1) {
    const isRightChild = currentIndex % 2 === 1;
    const siblingIndex = isRightChild ? currentIndex - 1 : currentIndex + 1;

    if (siblingIndex < currentLevel.length) {
      // Sibling exists
      proof.push((isRightChild ? 'L:' : 'R:') + currentLevel[siblingIndex]);
    } else {
      // Sibling is self (odd node)
      proof.push('R:' + currentLevel[currentIndex]);
    }

    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      if (i + 1 < currentLevel.length) {
        nextLevel.push(sha3_256Hex(currentLevel[i] + currentLevel[i + 1]));
      } else {
        nextLevel.push(sha3_256Hex(currentLevel[i] + currentLevel[i]));
      }
    }

    currentIndex = Math.floor(currentIndex / 2);
    currentLevel = nextLevel;
  }

  return proof;
}

/**
 * Verifies a Merkle inclusion proof against a known root.
 */
export function verifyMerkleProof(
  leafHash: string,
  proof: string[],
  merkleRoot: string
): boolean {
  let currentHash = leafHash;

  for (const step of proof) {
    const side = step.slice(0, 2);
    const siblingHash = step.slice(2);

    if (side === 'L:') {
      currentHash = sha3_256Hex(siblingHash + currentHash);
    } else {
      currentHash = sha3_256Hex(currentHash + siblingHash);
    }
  }

  return currentHash === merkleRoot;
}
