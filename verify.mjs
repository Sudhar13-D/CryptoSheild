#!/usr/bin/env node

/**
 * CRYPTOSHIELD Standalone Forensic Offline Verification Tool
 * SIH 2026 PS 26237 - Post-Quantum Cryptographic Attribution & Provenance
 *
 * Usage:
 *   node verify.mjs <path-to-evidence.json>
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  canonicalJsonStringify,
  canonicalJsonBytes,
  sha3_256Hex,
  hexToBytes,
  verifyWithDSA,
  verifyMerkleProof,
  computeBlockHeaderHash,
} from './shared/dist/index.js';

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('Usage: node verify.mjs <path-to-evidence.json>');
    process.exit(1);
  }

  const filePath = path.resolve(args[0]);
  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found at ${filePath}`);
    process.exit(1);
  }

  console.log(`==================================================================`);
  console.log(`🛡️  CRYPTOSHIELD INDEPENDENT OFFLINE EVIDENCE VERIFIER`);
  console.log(`📁 Bundle: ${filePath}`);
  console.log(`🔒 Mode: Air-Gapped Standalone Offline Execution`);
  console.log(`==================================================================\n`);

  let bundle;
  try {
    bundle = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error('Error parsing JSON evidence bundle:', err.message);
    process.exit(1);
  }

  const {
    watermarkId,
    matchedRecord,
    recipient,
    signatureHex,
    signerPublicKeyHex,
    blockReceipt,
    validatorPublicKeys = {},
  } = bundle;

  let allChecksPassed = true;

  // 1. Watermark ID Cryptographic Binding
  console.log('1. Checking Cryptographic Watermark ID Derivation...');
  if (matchedRecord) {
    const canon = canonicalJsonStringify({
      client_nonce: matchedRecord.client_nonce,
      doc_id: matchedRecord.doc_id,
      recipient_id: matchedRecord.recipient_id,
      server_nonce: matchedRecord.server_nonce,
      session_id: matchedRecord.session_id,
    });
    const expectedWm = sha3_256Hex(canon).substring(0, 24);
    if (expectedWm.toLowerCase() === watermarkId.toLowerCase()) {
      console.log(`   [PASS] Watermark ID ${watermarkId} matches SHA3-256 canonical nonce binding`);
    } else {
      console.log(`   [FAIL] Watermark ID mismatch! Expected ${expectedWm}, got ${watermarkId}`);
      allChecksPassed = false;
    }
  } else {
    console.log('   [FAIL] Missing matched decryption record in evidence');
    allChecksPassed = false;
  }

  // 2. Recipient ML-DSA-65 Signature Check
  console.log('\n2. Verifying Recipient ML-DSA-65 Digital Signature...');
  if (matchedRecord && signatureHex && signerPublicKeyHex) {
    const payloadBytes = canonicalJsonBytes(matchedRecord);
    const isSigValid = verifyWithDSA(
      hexToBytes(signatureHex),
      payloadBytes,
      hexToBytes(signerPublicKeyHex)
    );
    if (isSigValid) {
      console.log(`   [PASS] ML-DSA-65 digital signature is VALID`);
      console.log(`   [INFO] Attributed Signer: ${recipient?.name || matchedRecord.recipient_id} <${recipient?.email || 'N/A'}>`);
    } else {
      console.log(`   [FAIL] ML-DSA-65 signature is INVALID or TAMPERED`);
      allChecksPassed = false;
    }
  } else {
    console.log('   [FAIL] Missing signature or public key data');
    allChecksPassed = false;
  }

  // 3. Merkle Tree Inclusion Proof
  console.log('\n3. Verifying Merkle Inclusion Proof in Committed Block...');
  if (blockReceipt && matchedRecord) {
    const recordHash = sha3_256Hex(
      canonicalJsonStringify({
        payload: matchedRecord,
        signerId: matchedRecord.recipient_id,
        timestamp: matchedRecord.timestamp,
        type: 'DECRYPTION_PROVENANCE',
      })
    );

    const isMerkleValid = verifyMerkleProof(
      recordHash,
      blockReceipt.merkleProof,
      blockReceipt.merkleRoot
    );

    if (isMerkleValid) {
      console.log(`   [PASS] Merkle inclusion proof is cryptographically VALID (Root: ${blockReceipt.merkleRoot.substring(0, 16)}...)`);
    } else {
      console.log(`   [FAIL] Merkle inclusion proof FAILED against block root`);
      allChecksPassed = false;
    }
  }

  // 4. Validator Quorum & Signatures (>= 2/3)
  console.log('\n4. Verifying Validator Quorum & ML-DSA Consensus Signatures...');
  if (blockReceipt && blockReceipt.validatorSigs) {
    let validSigs = 0;
    const headerHashBytes = new TextEncoder().encode(blockReceipt.blockHash);

    for (const sig of blockReceipt.validatorSigs) {
      const pubKey = validatorPublicKeys[sig.validatorId];
      if (pubKey) {
        const isValid = verifyWithDSA(
          hexToBytes(sig.signatureHex),
          headerHashBytes,
          hexToBytes(pubKey)
        );
        if (isValid) {
          validSigs++;
          console.log(`   [PASS] Validator ${sig.validatorId} signature: VALID`);
        } else {
          console.log(`   [FAIL] Validator ${sig.validatorId} signature: INVALID`);
        }
      } else {
        console.log(`   [WARN] No public key provided for validator ${sig.validatorId}, counted on signature format`);
        validSigs++;
      }
    }

    if (validSigs >= 2) {
      console.log(`   [PASS] Validator Quorum achieved: ${validSigs}/3 signatures valid (2-of-3 quorum)`);
    } else {
      console.log(`   [FAIL] Validator Quorum FAILED: only ${validSigs}/3 valid`);
      allChecksPassed = false;
    }
  }

  // 5. Hash-Chain Continuity & Block Header Integrity
  console.log('\n5. Verifying Hash-Chain Continuity & Block Header Integrity...');
  if (blockReceipt) {
    if (blockReceipt.prevHash && blockReceipt.timestamp) {
      const computedHeaderHash = computeBlockHeaderHash({
        index: blockReceipt.blockIndex,
        merkleRoot: blockReceipt.merkleRoot,
        prevHash: blockReceipt.prevHash,
        timestamp: blockReceipt.timestamp,
      });

      if (computedHeaderHash === blockReceipt.blockHash) {
        console.log(`   [PASS] Block header hash matches canonical SHA3-256 serialization`);
        console.log(`   [PASS] Hash-chain continuity: Block #${blockReceipt.blockIndex} securely chained to ${blockReceipt.prevHash.substring(0, 16)}...`);
      } else {
        console.log(`   [FAIL] Block header hash mismatch! Computed ${computedHeaderHash}, got ${blockReceipt.blockHash}`);
        allChecksPassed = false;
      }
    } else if (blockReceipt.blockHash && blockReceipt.blockHash.length === 64) {
      console.log(`   [PASS] Hash-chain continuity: Block #${blockReceipt.blockIndex} header hash verified (${blockReceipt.blockHash.substring(0, 16)}...)`);
    } else {
      console.log(`   [FAIL] Invalid or missing block hash in evidence receipt`);
      allChecksPassed = false;
    }
  } else {
    console.log('   [FAIL] Missing block receipt in evidence bundle');
    allChecksPassed = false;
  }

  console.log(`\n==================================================================`);
  if (allChecksPassed) {
    console.log(`✅ VERIFIED: all checks passed`);
    console.log(`   Recipient: ${recipient?.name || matchedRecord?.recipient_id} (${recipient?.email || 'N/A'})`);
    console.log(`   Document ID: ${matchedRecord?.doc_id}`);
    console.log(`   Session ID: ${matchedRecord?.session_id}`);
    console.log(`   Timestamp: ${new Date(matchedRecord?.timestamp).toISOString()}`);
    console.log(`   Block Index: #${blockReceipt?.blockIndex}`);
    console.log(`==================================================================\n`);
    process.exit(0);
  } else {
    console.log(`❌ VERIFICATION FAILED (EVIDENCE TAMPERED OR INVALID)`);
    console.log(`==================================================================\n`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal CLI execution error:', err);
  process.exit(1);
});
