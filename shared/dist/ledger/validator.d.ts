import { Block, BlockHeader, LedgerRecord, UserRecord, ValidatorSignature } from '../types.js';
import { DsaKeyPair } from '../crypto/pqc.js';
export declare function computeBlockHeaderHash(header: BlockHeader): string;
export declare class ValidatorNode {
    readonly nodeId: string;
    readonly keyPair: DsaKeyPair;
    readonly chainFilePath: string;
    constructor(nodeId: string, chainFilePath: string, keyPair?: DsaKeyPair);
    getPublicKeyHex(): string;
    loadChain(): Block[];
    saveChain(chain: Block[]): void;
    /**
     * Verifies an individual record's integrity and ML-DSA signature
     */
    verifyRecord(record: LedgerRecord, directory?: Record<string, UserRecord>): boolean;
    /**
     * Independently validates a candidate block before signing
     */
    validateCandidateBlock(candidateHeader: BlockHeader, records: LedgerRecord[], lastBlock: Block | null, directory?: Record<string, UserRecord>): boolean;
    /**
     * Signs the candidate block header
     */
    signHeader(header: BlockHeader): ValidatorSignature;
    appendBlock(block: Block): void;
}
