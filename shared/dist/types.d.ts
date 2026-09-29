export type UserRole = 'owner' | 'recipient' | 'investigator' | 'admin';
export interface UserRecord {
    id: string;
    name: string;
    role: UserRole;
    email: string;
    mlKemPublicKeyHex: string;
    mlDsaPublicKeyHex: string;
    enrolledAt: number;
}
export interface RecipientKeyWrap {
    recipientId: string;
    kemCiphertextHex: string;
    wrappedK1Hex: string;
    wrapIvHex: string;
}
export interface EncryptedDocumentPackage {
    docId: string;
    docName: string;
    docHash: string;
    fileSize: number;
    pageCount: number;
    ownerId: string;
    createdAt: number;
    ciphertextHex: string;
    ivHex: string;
    recipients: Record<string, RecipientKeyWrap>;
}
export interface DecryptionSession {
    sessionId: string;
    docId: string;
    recipientId: string;
    serverNonce: string;
    createdAt: number;
    expiresAt: number;
}
export interface DecryptionRecord {
    doc_id: string;
    doc_hash: string;
    recipient_id: string;
    session_id: string;
    watermark_id: string;
    server_nonce: string;
    client_nonce: string;
    timestamp: number;
    alg: 'ML-DSA-65';
}
export interface SignedDecryptionRecord {
    record: DecryptionRecord;
    signatureHex: string;
    recipientPublicKeyHex: string;
}
export interface BlockReceipt {
    blockIndex: number;
    blockHash: string;
    prevHash?: string;
    timestamp?: number;
    merkleRoot: string;
    merkleProof: string[];
    validatorSigs: Array<{
        validatorId: string;
        signatureHex: string;
    }>;
}
export interface KeyReleaseResponse {
    blockReceipt: BlockReceipt;
    kemCiphertextHex: string;
    wrappedK2Hex: string;
    wrapIvHex: string;
}
export type LedgerRecordType = 'GENESIS' | 'USER_REGISTRATION' | 'DECRYPTION_PROVENANCE' | 'INVESTIGATION_APPROVAL';
export interface LedgerRecord {
    id: string;
    type: LedgerRecordType;
    timestamp: number;
    payload: Record<string, unknown>;
    signerId: string;
    signatureHex: string;
    signerPublicKeyHex: string;
    recordHash: string;
}
export interface BlockHeader {
    index: number;
    prevHash: string;
    timestamp: number;
    merkleRoot: string;
}
export interface ValidatorSignature {
    validatorId: string;
    signatureHex: string;
}
export interface Block {
    index: number;
    prevHash: string;
    timestamp: number;
    merkleRoot: string;
    records: LedgerRecord[];
    validatorSigs: ValidatorSignature[];
    blockHash: string;
}
export interface ChainVerificationResult {
    isValid: boolean;
    totalBlocks: number;
    divergentNodes: string[];
    validatorQuorumValid: boolean;
    nodeHeads: Record<string, {
        height: number;
        hash: string;
    }>;
    errors: string[];
}
export interface InvestigationApproval {
    caseId: string;
    investigatorId: string;
    approvedAt: number;
    signatureHex: string;
}
export interface ForensicCase {
    caseId: string;
    title: string;
    leakedFileName: string;
    uploadedAt: number;
    investigatorId: string;
    fileDataHex: string;
    approvals: InvestigationApproval[];
    status: 'PENDING_APPROVAL' | 'APPROVED' | 'EXTRACTED' | 'VERIFIED';
    extractionResult?: ForensicVerificationResult;
}
export interface ForensicVerificationResult {
    status: 'VERIFIED' | 'FAILED_CRC' | 'NOT_FOUND' | 'UNREGISTERED' | 'INVALID_SIG' | 'CHAIN_TAMPERED' | 'INSUFFICIENT_APPROVALS';
    watermarkFound: boolean;
    watermarkId: string | null;
    channel1Success: boolean;
    channel2Success: boolean;
    crcValid: boolean;
    matchedRecord: DecryptionRecord | null;
    recipient: UserRecord | null;
    signatureValid: boolean;
    merkleInclusionValid: boolean;
    validatorQuorumValid: boolean;
    chainIntegrityValid: boolean;
    divergentNodes: string[];
    reportSummary: string;
    blockReceipt?: BlockReceipt;
}
export interface RobustnessTestResult {
    attack: string;
    psnrDb: number;
    channel1Extracted: boolean;
    channel2Extracted: boolean;
    crcValid: boolean;
    watermarkMatched: boolean;
}
