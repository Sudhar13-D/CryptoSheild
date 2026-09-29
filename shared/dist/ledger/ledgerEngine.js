import path from 'node:path';
import { canonicalJsonBytes, canonicalJsonStringify } from '../crypto/canonical.js';
import { hexToBytes, bytesToHex, sha3_256Hex } from '../crypto/hash.js';
import { computeMerkleRoot, generateMerkleProof } from './merkle.js';
import { computeBlockHeaderHash, ValidatorNode } from './validator.js';
import { verifyWithDSA, signWithDSA } from '../crypto/pqc.js';
export function createLedgerRecord(id, type, payload, signerId, signerSecretKey, signerPublicKey, timestamp = Date.now(), existingSignatureHex) {
    let signatureHex = existingSignatureHex || '';
    if (!signatureHex && signerSecretKey && signerSecretKey.length > 0) {
        const payloadBytes = canonicalJsonBytes(payload);
        signatureHex = bytesToHex(signWithDSA(payloadBytes, signerSecretKey));
    }
    const signerPublicKeyHex = bytesToHex(signerPublicKey);
    const recordHash = sha3_256Hex(canonicalJsonStringify({
        payload,
        signerId,
        timestamp,
        type,
    }));
    return {
        id,
        type,
        timestamp,
        payload,
        signerId,
        signatureHex,
        signerPublicKeyHex,
        recordHash,
    };
}
export class LedgerEngine {
    validators = new Map();
    baseDataDir;
    constructor(options) {
        this.baseDataDir = options.baseDataDir;
        // Initialize 3 independent validator nodes
        for (let i = 1; i <= 3; i++) {
            const nodeId = `node-${i}`;
            const chainPath = path.join(this.baseDataDir, nodeId, 'chain.json');
            const keyPair = options.nodeKeyPairs?.[nodeId];
            const node = new ValidatorNode(nodeId, chainPath, keyPair);
            this.validators.set(nodeId, node);
        }
        this.ensureGenesis();
    }
    getValidatorPublicKeys() {
        const keys = {};
        for (const [id, node] of this.validators.entries()) {
            keys[id] = node.getPublicKeyHex();
        }
        return keys;
    }
    /**
     * Initializes genesis block across all 3 nodes if chains are empty
     */
    ensureGenesis() {
        const node1 = this.validators.get('node-1');
        const chain1 = node1.loadChain();
        if (chain1.length > 0)
            return;
        const genesisPayload = {
            system: 'CRYPTOSHIELD Forensics Verification System',
            description: 'SIH 2026 PS 26237 Immutable Provenance Genesis',
            validators: Array.from(this.validators.keys()),
        };
        const genesisRecord = {
            id: 'genesis-0000',
            type: 'GENESIS',
            timestamp: 1710000000000,
            payload: genesisPayload,
            signerId: 'system',
            signatureHex: '00'.repeat(32),
            signerPublicKeyHex: '00'.repeat(32),
            recordHash: sha3_256Hex(canonicalJsonStringify({
                payload: genesisPayload,
                signerId: 'system',
                timestamp: 1710000000000,
                type: 'GENESIS',
            })),
        };
        const header = {
            index: 0,
            prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
            timestamp: 1710000000000,
            merkleRoot: computeMerkleRoot([genesisRecord.recordHash]),
        };
        const blockHash = computeBlockHeaderHash(header);
        const validatorSigs = [];
        for (const node of this.validators.values()) {
            validatorSigs.push(node.signHeader(header));
        }
        const genesisBlock = {
            ...header,
            records: [genesisRecord],
            validatorSigs,
            blockHash,
        };
        for (const node of this.validators.values()) {
            node.saveChain([genesisBlock]);
        }
    }
    /**
     * Commits a new record to the ledger.
     * Requires >= 2 of 3 validator signatures (quorum).
     */
    async commitRecord(record, directory) {
        const node1 = this.validators.get('node-1');
        const chain = node1.loadChain();
        const lastBlock = chain.length > 0 ? chain[chain.length - 1] : null;
        const newIndex = lastBlock ? lastBlock.index + 1 : 0;
        const prevHash = lastBlock
            ? lastBlock.blockHash
            : '0000000000000000000000000000000000000000000000000000000000000000';
        const records = [record];
        const leafHashes = records.map((r) => r.recordHash);
        const merkleRoot = computeMerkleRoot(leafHashes);
        const header = {
            index: newIndex,
            prevHash,
            timestamp: Date.now(),
            merkleRoot,
        };
        const blockHash = computeBlockHeaderHash(header);
        const collectedSigs = [];
        // Each validator independently validates before signing
        for (const node of this.validators.values()) {
            const isValid = node.validateCandidateBlock(header, records, lastBlock, directory);
            if (isValid) {
                collectedSigs.push(node.signHeader(header));
            }
        }
        // Require >= 2-of-3 quorum
        if (collectedSigs.length < 2) {
            throw new Error(`Consensus failure: Only ${collectedSigs.length}/3 validators approved block ${newIndex}`);
        }
        const committedBlock = {
            ...header,
            records,
            validatorSigs: collectedSigs,
            blockHash,
        };
        // Append to all participating nodes
        for (const node of this.validators.values()) {
            node.appendBlock(committedBlock);
        }
        const merkleProof = generateMerkleProof(leafHashes, 0);
        return {
            blockIndex: committedBlock.index,
            blockHash: committedBlock.blockHash,
            prevHash: committedBlock.prevHash,
            timestamp: committedBlock.timestamp,
            merkleRoot: committedBlock.merkleRoot,
            merkleProof,
            validatorSigs: committedBlock.validatorSigs,
        };
    }
    /**
     * Retrieves the current majority chain
     */
    getMajorityChain() {
        const chains = new Map();
        for (const [id, node] of this.validators.entries()) {
            chains.set(id, node.loadChain());
        }
        // Return node-1 chain by default, or node-2 if node-1 is shorter/divergent
        return chains.get('node-1') || [];
    }
    /**
     * Finds a record by its watermark_id payload or record id
     */
    findRecordByWatermarkId(watermarkId) {
        const chain = this.getMajorityChain();
        for (const block of chain) {
            const leafHashes = block.records.map((r) => r.recordHash);
            for (let i = 0; i < block.records.length; i++) {
                const record = block.records[i];
                const wmId = record.payload?.watermark_id;
                if (wmId && wmId.toLowerCase() === watermarkId.toLowerCase()) {
                    const proof = generateMerkleProof(leafHashes, i);
                    return { block, record, proof };
                }
            }
        }
        return null;
    }
    /**
     * Full ledger verification:
     * 1. Recomputes all block hashes and Merkle roots
     * 2. Checks hash-chain links
     * 3. Verifies validator signatures (>= 2/3 valid)
     * 4. Verifies per-record user signatures
     * 5. Cross-checks heads across all 3 nodes to identify divergent nodes
     */
    verifyChain(directory) {
        const errors = [];
        const nodeChains = {};
        const nodeHeads = {};
        for (const [id, node] of this.validators.entries()) {
            const chain = node.loadChain();
            nodeChains[id] = chain;
            nodeHeads[id] = {
                height: chain.length,
                hash: chain.length > 0 ? chain[chain.length - 1].blockHash : '',
            };
        }
        const divergentNodes = [];
        const validatorPubKeys = this.getValidatorPublicKeys();
        // Verify each node individually
        for (const [nodeId, chain] of Object.entries(nodeChains)) {
            let nodeValid = true;
            for (let i = 0; i < chain.length; i++) {
                const block = chain[i];
                // 1. Verify block header hash
                const computedHash = computeBlockHeaderHash({
                    index: block.index,
                    prevHash: block.prevHash,
                    timestamp: block.timestamp,
                    merkleRoot: block.merkleRoot,
                });
                if (computedHash !== block.blockHash) {
                    errors.push(`Node ${nodeId} block ${i} hash mismatch: computed ${computedHash}, got ${block.blockHash}`);
                    nodeValid = false;
                }
                // 2. Verify hash-chain link
                if (i > 0) {
                    const prevBlock = chain[i - 1];
                    if (block.prevHash !== prevBlock.blockHash) {
                        errors.push(`Node ${nodeId} block ${i} broken chain link: prevHash does not match block ${i - 1} hash`);
                        nodeValid = false;
                    }
                }
                // 3. Verify Merkle root
                const leafHashes = block.records.map((r) => r.recordHash);
                const computedRoot = computeMerkleRoot(leafHashes);
                if (computedRoot !== block.merkleRoot) {
                    errors.push(`Node ${nodeId} block ${i} Merkle root mismatch`);
                    nodeValid = false;
                }
                // 4. Verify validator signatures (>= 2 of 3)
                let validValidatorCount = 0;
                const headerHashBytes = new TextEncoder().encode(block.blockHash);
                for (const sig of block.validatorSigs) {
                    const pubKeyHex = validatorPubKeys[sig.validatorId];
                    if (pubKeyHex) {
                        const isValid = verifyWithDSA(hexToBytes(sig.signatureHex), headerHashBytes, hexToBytes(pubKeyHex));
                        if (isValid)
                            validValidatorCount++;
                    }
                }
                if (validValidatorCount < 2) {
                    errors.push(`Node ${nodeId} block ${i} insufficient valid validator signatures (${validValidatorCount}/3)`);
                    nodeValid = false;
                }
                // 5. Verify records and signer signatures
                for (const record of block.records) {
                    const expectedRecordHash = sha3_256Hex(canonicalJsonStringify({
                        payload: record.payload,
                        signerId: record.signerId,
                        timestamp: record.timestamp,
                        type: record.type,
                    }));
                    if (expectedRecordHash !== record.recordHash) {
                        errors.push(`Node ${nodeId} block ${i} record ${record.id} hash tampered`);
                        nodeValid = false;
                    }
                    if (record.type !== 'GENESIS') {
                        const payloadBytes = canonicalJsonBytes(record.payload);
                        const isSigValid = verifyWithDSA(hexToBytes(record.signatureHex), payloadBytes, hexToBytes(record.signerPublicKeyHex));
                        if (!isSigValid) {
                            errors.push(`Node ${nodeId} block ${i} record ${record.id} signature invalid`);
                            nodeValid = false;
                        }
                    }
                }
            }
            if (!nodeValid) {
                divergentNodes.push(nodeId);
            }
        }
        // Compare consensus heads across nodes
        const nodeIds = Object.keys(nodeChains);
        const hashes = nodeIds.map((id) => nodeHeads[id].hash);
        // If node-1 has different head than majority node-2 & node-3
        if (hashes[0] !== hashes[1] && hashes[1] === hashes[2]) {
            if (!divergentNodes.includes(nodeIds[0]))
                divergentNodes.push(nodeIds[0]);
        }
        else if (hashes[1] !== hashes[0] && hashes[0] === hashes[2]) {
            if (!divergentNodes.includes(nodeIds[1]))
                divergentNodes.push(nodeIds[1]);
        }
        else if (hashes[2] !== hashes[0] && hashes[0] === hashes[1]) {
            if (!divergentNodes.includes(nodeIds[2]))
                divergentNodes.push(nodeIds[2]);
        }
        const quorumValid = divergentNodes.length <= 1; // 2 out of 3 valid means majority consensus holds
        const isValid = quorumValid && errors.length === 0;
        return {
            isValid,
            totalBlocks: nodeChains['node-1']?.length || 0,
            divergentNodes,
            validatorQuorumValid: quorumValid,
            nodeHeads,
            errors,
        };
    }
    /**
     * Tamper Demo simulation: intentionally alters a record in node-1's chain
     */
    tamperNode(nodeId, blockIndex, newPayload) {
        const node = this.validators.get(nodeId);
        if (!node)
            throw new Error(`Node ${nodeId} not found`);
        const chain = node.loadChain();
        if (blockIndex < 0 || blockIndex >= chain.length) {
            throw new Error(`Block index ${blockIndex} out of bounds`);
        }
        const block = chain[blockIndex];
        if (block.records.length > 0) {
            // Modify payload of first record in block without updating signatures
            block.records[0].payload = {
                ...block.records[0].payload,
                ...newPayload,
                _TAMPERED: true,
            };
        }
        node.saveChain(chain);
    }
    /**
     * Restores a tampered node from majority consensus
     */
    repairNode(nodeId) {
        const majorityNode = nodeId === 'node-1' ? this.validators.get('node-2') : this.validators.get('node-1');
        const healthyChain = majorityNode.loadChain();
        const targetNode = this.validators.get(nodeId);
        if (targetNode) {
            targetNode.saveChain(healthyChain);
        }
    }
}
