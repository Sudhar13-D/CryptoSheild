import { Block, BlockReceipt, ChainVerificationResult, LedgerRecord, UserRecord } from '../types.js';
import { ValidatorNode } from './validator.js';
import { DsaKeyPair } from '../crypto/pqc.js';
import { LedgerRecordType } from '../types.js';
export declare function createLedgerRecord(id: string, type: LedgerRecordType, payload: Record<string, unknown>, signerId: string, signerSecretKey: Uint8Array | null, signerPublicKey: Uint8Array, timestamp?: number, existingSignatureHex?: string): LedgerRecord;
export interface LedgerEngineOptions {
    baseDataDir: string;
    nodeKeyPairs?: Record<string, DsaKeyPair>;
}
export declare class LedgerEngine {
    readonly validators: Map<string, ValidatorNode>;
    readonly baseDataDir: string;
    constructor(options: LedgerEngineOptions);
    getValidatorPublicKeys(): Record<string, string>;
    /**
     * Initializes genesis block across all 3 nodes if chains are empty
     */
    ensureGenesis(): void;
    /**
     * Commits a new record to the ledger.
     * Requires >= 2 of 3 validator signatures (quorum).
     */
    commitRecord(record: LedgerRecord, directory?: Record<string, UserRecord>): Promise<BlockReceipt>;
    /**
     * Retrieves the current majority chain
     */
    getMajorityChain(): Block[];
    /**
     * Finds a record by its watermark_id payload or record id
     */
    findRecordByWatermarkId(watermarkId: string): {
        block: Block;
        record: LedgerRecord;
        proof: string[];
    } | null;
    /**
     * Full ledger verification:
     * 1. Recomputes all block hashes and Merkle roots
     * 2. Checks hash-chain links
     * 3. Verifies validator signatures (>= 2/3 valid)
     * 4. Verifies per-record user signatures
     * 5. Cross-checks heads across all 3 nodes to identify divergent nodes
     */
    verifyChain(directory?: Record<string, UserRecord>): ChainVerificationResult;
    /**
     * Tamper Demo simulation: intentionally alters a record in node-1's chain
     */
    tamperNode(nodeId: string, blockIndex: number, newPayload: Record<string, unknown>): void;
    /**
     * Restores a tampered node from majority consensus
     */
    repairNode(nodeId: string): void;
}
