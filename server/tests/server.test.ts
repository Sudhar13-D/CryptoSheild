import { describe, it, expect, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  generateKeyPairKEM,
  generateKeyPairDSA,
  bytesToHex,
  hexToBytes,
  signWithDSA,
  canonicalJsonBytes,
  canonicalJsonStringify,
  sha3_256Hex,
} from '@cryptoshield/shared';
import { ServerStore } from '../src/store.js';
import { createApp } from '../src/app.js';

describe('Server & Commit-Before-Release API Integration Tests', () => {
  const createdDirs: string[] = [];

  function createTestEnv() {
    const testDir = path.join(
      process.cwd(),
      'data',
      `test-srv-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`
    );
    createdDirs.push(testDir);
    const store = new ServerStore(testDir);
    const app = createApp(store) as unknown as Express.Application;

    const aliceKem = generateKeyPairKEM();
    const aliceDsa = generateKeyPairDSA();

    store.saveUser({
      id: 'test_alice',
      name: 'Test Alice',
      role: 'recipient',
      email: 'alice@test.local',
      mlKemPublicKeyHex: bytesToHex(aliceKem.publicKey),
      mlDsaPublicKeyHex: bytesToHex(aliceDsa.publicKey),
      enrolledAt: Date.now(),
    });

    store.saveDocument({
      docId: 'doc-test-1',
      docName: 'Test Classified Document',
      docHash: sha3_256Hex('ORIGINAL_PDF_MOCK'),
      fileSize: 1024,
      pageCount: 1,
      ownerId: 'owner@org',
      createdAt: Date.now(),
      ciphertextHex: 'deadbeef',
      ivHex: '123456789012',
      recipients: {
        test_alice: {
          recipientId: 'test_alice',
          kemCiphertextHex: 'aa',
          wrappedK1Hex: 'bb',
          wrapIvHex: 'cc',
        },
      },
    });
    store.saveK2Key('doc-test-1', '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff');

    return { store, app, aliceKem, aliceDsa };
  }

  afterAll(() => {
    for (const dir of createdDirs) {
      try {
        if (fs.existsSync(dir)) {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      } catch {
        // Ignore busy handles on cleanup
      }
    }
  });

  it('COMMIT-BEFORE-RELEASE: K2 refused without valid committed decryption record', async () => {
    const { app, aliceDsa } = createTestEnv();

    // 1. Request session
    const sessRes = await request(app)
      .post('/api/decrypt/session')
      .send({ docId: 'doc-test-1', recipientId: 'test_alice' });
    expect(sessRes.status).toBe(200);
    const { sessionId, serverNonce } = sessRes.body;

    // 2. Attempt commit with invalid signature -> K2 must be refused!
    const clientNonce = '112233445566';
    const fakeWatermarkId = '00112233445566778899aabb';
    const decRecord = {
      doc_id: 'doc-test-1',
      doc_hash: sha3_256Hex('ORIGINAL_PDF_MOCK'),
      recipient_id: 'test_alice',
      session_id: sessionId,
      watermark_id: fakeWatermarkId,
      server_nonce: serverNonce,
      client_nonce: clientNonce,
      timestamp: Date.now(),
      alg: 'ML-DSA-65' as const,
    };

    const forgedSignature = bytesToHex(new Uint8Array(3309)); // Fake signature

    const badCommitRes = await request(app)
      .post('/api/decrypt/commit-and-release')
      .send({
        docId: 'doc-test-1',
        recipientId: 'test_alice',
        signedRecord: {
          record: decRecord,
          signatureHex: forgedSignature,
          recipientPublicKeyHex: bytesToHex(aliceDsa.publicKey),
        },
      });

    // Expect refusal (400)
    expect(badCommitRes.status).toBe(400);
    expect(badCommitRes.body.wrappedK2Hex).toBeUndefined();
  });

  it('COMMIT-BEFORE-RELEASE: Replayed session record is strictly rejected', async () => {
    const { app, aliceDsa } = createTestEnv();

    // 1. Request valid session
    const sessRes = await request(app)
      .post('/api/decrypt/session')
      .send({ docId: 'doc-test-1', recipientId: 'test_alice' });
    const { sessionId, serverNonce } = sessRes.body;

    const clientNonce = 'aabbccddeeff';
    const canon = canonicalJsonStringify({
      client_nonce: clientNonce,
      doc_id: 'doc-test-1',
      recipient_id: 'test_alice',
      server_nonce: serverNonce,
      session_id: sessionId,
    });
    const watermarkId = sha3_256Hex(canon).substring(0, 24);

    const decRecord = {
      doc_id: 'doc-test-1',
      doc_hash: sha3_256Hex('ORIGINAL_PDF_MOCK'),
      recipient_id: 'test_alice',
      session_id: sessionId,
      watermark_id: watermarkId,
      server_nonce: serverNonce,
      client_nonce: clientNonce,
      timestamp: Date.now(),
      alg: 'ML-DSA-65' as const,
    };

    const signature = signWithDSA(canonicalJsonBytes(decRecord), aliceDsa.secretKey);

    const signedPayload = {
      docId: 'doc-test-1',
      recipientId: 'test_alice',
      signedRecord: {
        record: decRecord,
        signatureHex: bytesToHex(signature),
        recipientPublicKeyHex: bytesToHex(aliceDsa.publicKey),
      },
    };

    // First commit -> Must succeed
    const firstRes = await request(app)
      .post('/api/decrypt/commit-and-release')
      .send(signedPayload);
    expect(firstRes.status).toBe(200);
    expect(firstRes.body.wrappedK2Hex).toBeDefined();

    // Second commit with same session -> Replay attack must be rejected!
    const replayRes = await request(app)
      .post('/api/decrypt/commit-and-release')
      .send(signedPayload);
    expect(replayRes.status).toBe(400);
    expect(replayRes.body.error).toContain('replay detected');
  });

  it('FORENSIC PROTOCOL: Case extraction is strictly blocked with < 2 investigator approvals', async () => {
    const { app, store } = createTestEnv();

    // 1. Create a forensic case
    const caseRes = await request(app)
      .post('/api/forensics/cases')
      .send({
        title: 'Unauthorized Leak Inquest',
        leakedFileName: 'leaked_doc.pdf',
        fileDataHex: '255044462d312e34', // PDF magic header hex
        investigatorId: 'inv1',
      });
    expect(caseRes.status).toBe(200);
    const { caseId } = caseRes.body;

    // 2. Attempt extraction immediately (0 approvals) -> Expect 403 Forbidden
    const noApprovalRes = await request(app)
      .post(`/api/forensics/cases/${caseId}/extract`)
      .send({});
    expect(noApprovalRes.status).toBe(403);
    expect(noApprovalRes.body.status).toBe('INSUFFICIENT_APPROVALS');

    // 3. Register investigator 1 & 2
    const inv1Dsa = generateKeyPairDSA();
    const inv2Dsa = generateKeyPairDSA();
    store.saveUser({
      id: 'inv1',
      name: 'Investigator 1',
      role: 'investigator',
      email: 'inv1@local',
      mlKemPublicKeyHex: '00',
      mlDsaPublicKeyHex: bytesToHex(inv1Dsa.publicKey),
      enrolledAt: Date.now(),
    });
    store.saveUser({
      id: 'inv2',
      name: 'Investigator 2',
      role: 'investigator',
      email: 'inv2@local',
      mlKemPublicKeyHex: '00',
      mlDsaPublicKeyHex: bytesToHex(inv2Dsa.publicKey),
      enrolledAt: Date.now(),
    });

    // 4. Add 1 approval from inv1
    const app1Payload = { caseId, investigatorId: 'inv1', timestamp: Date.now() };
    const app1Sig = signWithDSA(canonicalJsonBytes(app1Payload), inv1Dsa.secretKey);
    const app1Res = await request(app)
      .post(`/api/forensics/cases/${caseId}/approve`)
      .send({ investigatorId: 'inv1', timestamp: app1Payload.timestamp, signatureHex: bytesToHex(app1Sig) });
    expect(app1Res.status).toBe(200);
    expect(app1Res.body.approvalsCount).toBe(1);

    // 5. Attempt extraction with only 1 approval -> Still expect 403 Forbidden!
    const oneApprovalRes = await request(app)
      .post(`/api/forensics/cases/${caseId}/extract`)
      .send({});
    expect(oneApprovalRes.status).toBe(403);
    expect(oneApprovalRes.body.status).toBe('INSUFFICIENT_APPROVALS');

    // 6. Add second approval from inv2
    const app2Payload = { caseId, investigatorId: 'inv2', timestamp: Date.now() };
    const app2Sig = signWithDSA(canonicalJsonBytes(app2Payload), inv2Dsa.secretKey);
    const app2Res = await request(app)
      .post(`/api/forensics/cases/${caseId}/approve`)
      .send({ investigatorId: 'inv2', timestamp: app2Payload.timestamp, signatureHex: bytesToHex(app2Sig) });
    expect(app2Res.status).toBe(200);
    expect(app2Res.body.approvalsCount).toBe(2);
    expect(app2Res.body.status).toBe('APPROVED');

    // 7. Now extraction is authorized to run!
    const allowedRes = await request(app)
      .post(`/api/forensics/cases/${caseId}/extract`)
      .send({ watermarkIdOverride: 'nonexistent123456789012' });
    expect(allowedRes.status).toBe(200); // Authorized (even if watermark not in ledger, request was permitted)
    expect(allowedRes.body.status).toBe('UNREGISTERED');
  });

  it('STANDALONE VERIFIER: verify.mjs rejects tampered evidence bundle and exits non-zero', () => {
    const validEvidencePath = path.join(process.cwd(), 'data', 'test_evidence_bundle.json');
    if (!fs.existsSync(validEvidencePath)) {
      // Create minimal valid signed bundle if file doesn't exist yet
      const dsa = generateKeyPairDSA();
      const rec = {
        client_nonce: 'c_test',
        doc_id: 'd_test',
        recipient_id: 'r_test',
        server_nonce: 's_test',
        session_id: 'sess_test',
        timestamp: Date.now(),
      };
      const canon = canonicalJsonStringify(rec);
      const wm = sha3_256Hex(canon).substring(0, 24);
      const sig = signWithDSA(canonicalJsonBytes(rec), dsa.secretKey);
      const bundle = {
        watermarkId: wm,
        matchedRecord: rec,
        recipient: { name: 'Test', email: 'test@local' },
        signatureHex: bytesToHex(sig),
        signerPublicKeyHex: bytesToHex(dsa.publicKey),
        blockReceipt: {
          blockIndex: 1,
          blockHash: 'aa'.repeat(32),
          merkleRoot: 'bb'.repeat(32),
          merkleProof: [],
          validatorSigs: [],
        },
      };
      fs.writeFileSync(validEvidencePath, JSON.stringify(bundle, null, 2), 'utf8');
    }

    const validContent = fs.readFileSync(validEvidencePath, 'utf8');
    const bundle = JSON.parse(validContent);

    // Tamper by flipping one byte in signatureHex
    const originalSig = bundle.signatureHex;
    const tamperedChar = originalSig[0] === 'a' ? 'b' : 'a';
    bundle.signatureHex = tamperedChar + originalSig.slice(1);

    const tempTamperedPath = path.join(process.cwd(), 'data', `tampered_evidence_${Date.now()}.json`);
    fs.writeFileSync(tempTamperedPath, JSON.stringify(bundle, null, 2), 'utf8');

    try {
      const result = spawnSync('node', ['verify.mjs', tempTamperedPath], {
        cwd: process.cwd(),
        encoding: 'utf8',
      });

      // Must exit non-zero!
      expect(result.status).not.toBe(0);
      expect(result.status).toBe(1);
      expect(result.stdout).toContain('VERIFICATION FAILED');
    } finally {
      if (fs.existsSync(tempTamperedPath)) {
        fs.unlinkSync(tempTamperedPath);
      }
    }
  });
});
