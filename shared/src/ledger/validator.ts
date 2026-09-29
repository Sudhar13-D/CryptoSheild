import fs from 'node:fs';
import path from 'node:path';
import {
  Block,
  BlockHeader,
  LedgerRecord,
  UserRecord,
  ValidatorSignature,
} from '../types.js';
import { canonicalJsonBytes, canonicalJsonStringify } from '../crypto/canonical.js';
import { hexToBytes, bytesToHex, sha3_256Hex } from '../crypto/hash.js';
import { computeMerkleRoot } from './merkle.js';
import { signWithDSA, verifyWithDSA, generateKeyPairDSA, DsaKeyPair } from '../crypto/pqc.js';

export function computeBlockHeaderHash(header: BlockHeader): string {
  const canonical = canonicalJsonStringify({
    index: header.index,
    merkleRoot: header.merkleRoot,
    prevHash: header.prevHash,
    timestamp: header.timestamp,
  });
  return sha3_256Hex(canonical);
}

export class ValidatorNode {
  public readonly nodeId: string;
  public readonly keyPair: DsaKeyPair;
  public readonly chainFilePath: string;

  constructor(nodeId: string, chainFilePath: string, keyPair?: DsaKeyPair) {
    this.nodeId = nodeId;
    this.chainFilePath = chainFilePath;

    // Ensure storage directory exists
    const dir = path.dirname(this.chainFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const keyFilePath = path.join(dir, 'validator-key.json');
    if (keyPair) {
      this.keyPair = keyPair;
      fs.writeFileSync(
        keyFilePath,
        JSON.stringify({
          publicKeyHex: bytesToHex(this.keyPair.publicKey),
          secretKeyHex: bytesToHex(this.keyPair.secretKey),
        })
      );
    } else if (fs.existsSync(keyFilePath)) {
      try {
        const saved = JSON.parse(fs.readFileSync(keyFilePath, 'utf8'));
        this.keyPair = {
          publicKey: hexToBytes(saved.publicKeyHex),
          secretKey: hexToBytes(saved.secretKeyHex),
        };
      } catch {
        this.keyPair = generateKeyPairDSA();
      }
    } else {
      this.keyPair = generateKeyPairDSA();
      fs.writeFileSync(
        keyFilePath,
        JSON.stringify({
          publicKeyHex: bytesToHex(this.keyPair.publicKey),
          secretKeyHex: bytesToHex(this.keyPair.secretKey),
        })
      );
    }
  }

  public getPublicKeyHex(): string {
    return bytesToHex(this.keyPair.publicKey);
  }

  public loadChain(): Block[] {
    if (!fs.existsSync(this.chainFilePath)) {
      return [];
    }
    try {
      const data = fs.readFileSync(this.chainFilePath, 'utf8');
      return JSON.parse(data) as Block[];
    } catch {
      return [];
    }
  }

  public saveChain(chain: Block[]): void {
    fs.writeFileSync(this.chainFilePath, JSON.stringify(chain, null, 2), 'utf8');
  }

  /**
   * Verifies an individual record's integrity and ML-DSA signature
   */
  public verifyRecord(record: LedgerRecord, directory?: Record<string, UserRecord>): boolean {
    // 1. Verify record hash
    const expectedHash = sha3_256Hex(
      canonicalJsonStringify({
        payload: record.payload,
        signerId: record.signerId,
        timestamp: record.timestamp,
        type: record.type,
      })
    );
    if (record.recordHash !== expectedHash) {
      return false;
    }

    // Genesis records are self-contained
    if (record.type === 'GENESIS') {
      return true;
    }

    // 2. Verify against directory if present
    if (directory && directory[record.signerId]) {
      const dirKey = directory[record.signerId].mlDsaPublicKeyHex;
      if (dirKey.toLowerCase() !== record.signerPublicKeyHex.toLowerCase()) {
        return false;
      }
    }

    // 3. Verify ML-DSA-65 signature on payload
    const payloadBytes = canonicalJsonBytes(record.payload);
    const sigBytes = hexToBytes(record.signatureHex);
    const pubKeyBytes = hexToBytes(record.signerPublicKeyHex);

    return verifyWithDSA(sigBytes, payloadBytes, pubKeyBytes);
  }

  /**
   * Independently validates a candidate block before signing
   */
  public validateCandidateBlock(
    candidateHeader: BlockHeader,
    records: LedgerRecord[],
    lastBlock: Block | null,
    directory?: Record<string, UserRecord>
  ): boolean {
    // 1. Validate index and prevHash
    if (lastBlock === null) {
      if (candidateHeader.index !== 0 || candidateHeader.prevHash !== '0000000000000000000000000000000000000000000000000000000000000000') {
        return false;
      }
    } else {
      if (candidateHeader.index !== lastBlock.index + 1) {
        return false;
      }
      if (candidateHeader.prevHash !== lastBlock.blockHash) {
        return false;
      }
    }

    // 2. Validate Merkle root
    const leafHashes = records.map((r) => r.recordHash);
    const computedRoot = computeMerkleRoot(leafHashes);
    if (candidateHeader.merkleRoot !== computedRoot) {
      return false;
    }

    // 3. Validate every record signature
    for (const record of records) {
      if (!this.verifyRecord(record, directory)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Signs the candidate block header
   */
  public signHeader(header: BlockHeader): ValidatorSignature {
    const headerHash = computeBlockHeaderHash(header);
    const sigBytes = signWithDSA(new TextEncoder().encode(headerHash), this.keyPair.secretKey);
    return {
      validatorId: this.nodeId,
      signatureHex: bytesToHex(sigBytes),
    };
  }

  public appendBlock(block: Block): void {
    const chain = this.loadChain();
    chain.push(block);
    this.saveChain(chain);
  }
}
