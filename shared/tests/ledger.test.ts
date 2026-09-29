import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  LedgerEngine,
  createLedgerRecord,
  generateKeyPairDSA,
  verifyMerkleProof,
} from '../src/index.js';

describe('Ledger & 3-Validator Consensus Engine', () => {
  const createdDirs: string[] = [];

  function createTestEngine() {
    const testDir = path.join(
      process.cwd(),
      'data',
      `test-ledg-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`
    );
    createdDirs.push(testDir);
    return new LedgerEngine({ baseDataDir: testDir });
  }

  afterAll(() => {
    for (const dir of createdDirs) {
      try {
        if (fs.existsSync(dir)) {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      } catch {
        // Ignore busy handles
      }
    }
  });

  it('Ledger initializes genesis block across all 3 nodes and commits record with 2-of-3 quorum', async () => {
    const engine = createTestEngine();

    const clientKeyPair = generateKeyPairDSA();
    const payload = {
      doc_id: 'doc-alpha-123',
      recipient_id: 'alice',
      session_id: 'session-xyz',
      watermark_id: '1234567890abcdef12345678',
      server_nonce: 'srv_nonce_1',
      client_nonce: 'cli_nonce_1',
      timestamp: Date.now(),
      alg: 'ML-DSA-65',
    };

    const record = createLedgerRecord(
      'rec-1',
      'DECRYPTION_PROVENANCE',
      payload,
      'alice',
      clientKeyPair.secretKey,
      clientKeyPair.publicKey
    );

    // Commit record
    const receipt = await engine.commitRecord(record);
    expect(receipt.blockIndex).toBe(1);
    expect(receipt.validatorSigs.length).toBeGreaterThanOrEqual(2);
    expect(receipt.merkleProof).toBeDefined();

    // Verify Merkle inclusion proof
    const isMerkleValid = verifyMerkleProof(
      record.recordHash,
      receipt.merkleProof,
      receipt.merkleRoot
    );
    expect(isMerkleValid).toBe(true);

    // Verify full chain across 3 nodes
    const verifyResult = engine.verifyChain();
    expect(verifyResult.isValid).toBe(true);
    expect(verifyResult.divergentNodes.length).toBe(0);
    expect(verifyResult.validatorQuorumValid).toBe(true);
  });

  it('Tamper Demo: Modifying node-1 flags node-1 as divergent while 2-node majority consensus remains valid', async () => {
    const engine = createTestEngine();

    const clientKeyPair = generateKeyPairDSA();
    const payload = {
      doc_id: 'doc-beta-456',
      recipient_id: 'bob',
      watermark_id: 'aabbccddeeff001122334455',
    };

    const record = createLedgerRecord(
      'rec-bob-1',
      'DECRYPTION_PROVENANCE',
      payload,
      'bob',
      clientKeyPair.secretKey,
      clientKeyPair.publicKey
    );

    await engine.commitRecord(record);

    // Tamper with node-1 block 1 payload
    engine.tamperNode('node-1', 1, { recipient_id: 'attacker_hacked' });

    // Verify chain: node-1 must be detected as divergent!
    const verifyResult = engine.verifyChain();
    expect(verifyResult.divergentNodes).toContain('node-1');
    expect(verifyResult.validatorQuorumValid).toBe(true); // 2-of-3 majority (node-2 and node-3) still valid!
    expect(verifyResult.isValid).toBe(false); // Flags that an anomaly exists

    // Repair node-1 from consensus
    engine.repairNode('node-1');
    const repairedResult = engine.verifyChain();
    expect(repairedResult.isValid).toBe(true);
    expect(repairedResult.divergentNodes.length).toBe(0);
  });
});
