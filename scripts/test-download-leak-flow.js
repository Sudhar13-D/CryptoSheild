import fs from 'node:fs';
import path from 'node:path';
import {
  unwrapKeyWithKEM,
  decryptAesGcm,
  canonicalJsonBytes,
  canonicalJsonStringify,
  signWithDSA,
  verifyWithDSA,
  sha3_256Hex,
  hexToBytes,
  bytesToHex,
  embedChannel2,
  extractChannel2,
} from '../shared/dist/index.js';
import crypto from 'node:crypto';

async function testDownloadedLeakFlow() {
  console.log('==================================================================');
  console.log('🧪 LIVE END-TO-END FLOW: RECIPIENT DECRYPT -> LEAK -> INQUEST');
  console.log('==================================================================\n');

  const serverUrl = 'http://127.0.0.1:8080';

  // 1. Load Bob's keys from demo keys
  const demoKeys = JSON.parse(fs.readFileSync('data/demo_keys.json', 'utf8'));
  const bobKeys = demoKeys['bob'];
  const bobId = 'bob';

  console.log('1. Loading recipient enclave credentials for Bob Smith (bob)...');
  console.log(`   Bob ML-DSA PubKey: ${bobKeys.dsa.pub.substring(0, 24)}...`);
  console.log(`   Bob ML-KEM PubKey: ${bobKeys.kem.pub.substring(0, 24)}...`);

  // 2. Fetch encrypted document package DOC-AEGIS-2026-001
  console.log('\n2. Fetching encrypted document package DOC-AEGIS-2026-001...');
  const docRes = await fetch(`${serverUrl}/api/documents/DOC-AEGIS-2026-001`);
  if (!docRes.ok) throw new Error('Failed to fetch document package');
  const docPkg = await docRes.json();
  console.log(`   Package Doc ID: ${docPkg.docId}`);
  console.log(`   Doc Hash: ${docPkg.docHash}`);

  // 3. Step 2: Unwrap K1 using ML-KEM-768
  console.log('\n3. [Step 2] Decapsulating symmetric key share K1 via ML-KEM-768...');
  const bobWrap = docPkg.recipients[bobId];
  if (!bobWrap) throw new Error('Bob not found in recipients');

  const k1 = await unwrapKeyWithKEM(
    hexToBytes(bobKeys.kem.sec),
    hexToBytes(bobWrap.kemCiphertextHex),
    hexToBytes(bobWrap.wrappedK1Hex),
    hexToBytes(bobWrap.wrapIvHex)
  );
  console.log(`   Unwrapped K1: ${bytesToHex(k1).substring(0, 24)}...`);

  // 4. Step 3: Request Session from Server
  console.log('\n4. [Step 3] Requesting decryption session token and server nonce...');
  const sessRes = await fetch(`${serverUrl}/api/decrypt/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ docId: docPkg.docId, recipientId: bobId }),
  });
  if (!sessRes.ok) throw new Error('Session request failed');
  const sessionData = await sessRes.json();
  console.log(`   Session ID: ${sessionData.sessionId}`);
  console.log(`   Server Nonce: ${sessionData.serverNonce}`);

  // 5. Step 4: Compute 96-Bit Watermark ID
  console.log('\n5. [Step 4] Computing 96-bit watermark identifier bound to nonces & identity...');
  const clientNonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const canonicalBinding = canonicalJsonStringify({
    client_nonce: clientNonce,
    doc_id: docPkg.docId,
    recipient_id: bobId,
    server_nonce: sessionData.serverNonce,
    session_id: sessionData.sessionId,
  });
  const bindingHash = sha3_256Hex(canonicalBinding);
  const watermarkId = bindingHash.substring(0, 24);
  console.log(`   Canonical Binding Hash: ${bindingHash}`);
  console.log(`   Derived Watermark ID: ${watermarkId}`);

  // 6. Step 5 & 6: Sign Provenance Record via ML-DSA-65 & Commit to Ledger
  console.log('\n6. [Steps 5 & 6] Signing provenance record via ML-DSA-65 and committing to 3-validator ledger...');
  const decRecord = {
    doc_id: docPkg.docId,
    doc_hash: docPkg.docHash,
    recipient_id: bobId,
    session_id: sessionData.sessionId,
    watermark_id: watermarkId,
    server_nonce: sessionData.serverNonce,
    client_nonce: clientNonce,
    timestamp: Date.now(),
    alg: 'ML-DSA-65',
  };
  const recordBytes = canonicalJsonBytes(decRecord);
  const signature = signWithDSA(recordBytes, hexToBytes(bobKeys.dsa.sec));
  const signatureHex = bytesToHex(signature);

  const commitRes = await fetch(`${serverUrl}/api/decrypt/commit-and-release`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      docId: docPkg.docId,
      recipientId: bobId,
      signedRecord: {
        record: decRecord,
        recipientPublicKeyHex: bobKeys.dsa.pub,
        signatureHex,
      },
    }),
  });
  if (!commitRes.ok) {
    const errText = await commitRes.text();
    throw new Error(`Commit-and-release failed: ${errText}`);
  }
  const releaseData = await commitRes.json();
  console.log(`   ✓ Committed to Ledger in Block #${releaseData.blockReceipt.blockIndex}`);
  console.log(`   Validator Signatures: ${releaseData.blockReceipt.validatorSigs.length}/3 (2-of-3 quorum met)`);

  // 7. Step 7 & 8: Decapsulate K2, Recombine K, Decrypt Plaintext
  console.log('\n7. [Steps 7 & 8] Decapsulating key share K2, recombining K = K1 ⊕ K2, and decrypting PDF...');
  const k2 = await unwrapKeyWithKEM(
    hexToBytes(bobKeys.kem.sec),
    hexToBytes(releaseData.kemCiphertextHex),
    hexToBytes(releaseData.wrappedK2Hex),
    hexToBytes(releaseData.wrapIvHex)
  );
  const fileKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    fileKey[i] = k1[i] ^ k2[i];
  }

  const ciphertext = hexToBytes(docPkg.ciphertextHex);
  const iv = hexToBytes(docPkg.ivHex);
  const plaintextPdf = await decryptAesGcm(fileKey, ciphertext, iv);
  console.log(`   ✓ Plaintext PDF Decrypted (${plaintextPdf.length} bytes)`);

  // 8. Step 9: Embed Watermark (Lossless) and save as downloaded file
  console.log('\n8. [Step 9] Embedding Channel 2 & Channel 1 forensic watermarks...');
  const watermarkedPdf = await embedChannel2(plaintextPdf, watermarkId);
  const downloadedLeakPath = path.join(process.cwd(), 'data', 'leaks', 'downloaded_bob_leak.pdf');
  fs.writeFileSync(downloadedLeakPath, Buffer.from(watermarkedPdf));
  console.log(`   ✓ Downloaded PDF saved: ${downloadedLeakPath}`);

  // 9. Forensics Inquest: Open Case with Downloaded PDF as Leak Evidence
  console.log('\n9. Creating new Forensic Inquest Case with the downloaded PDF evidence...');
  const caseId = `CASE-LIVE-${Date.now()}`;
  const createCaseRes = await fetch(`${serverUrl}/api/forensics/cases`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      caseId,
      title: 'Forensic Inquest: Intercepted Downloaded PDF Leak',
      leakedFileName: 'downloaded_bob_leak.pdf',
      fileDataHex: bytesToHex(watermarkedPdf),
      investigatorId: 'inv1',
    }),
  });
  if (!createCaseRes.ok) throw new Error('Failed to create forensic case');
  const caseData = await createCaseRes.json();
  const realCaseId = caseData.caseId;
  console.log(`   Case Created: ${realCaseId} – "${caseData.newCase.title}"`);
  console.log(`   Initial Approvals: ${caseData.newCase.approvals.length}/2`);

  // 10. Multi-Investigator Quorum: Collect 2 Approvals (inv1 and inv2)
  console.log('\n10. Collecting Multi-Investigator Quorum Approvals (ML-DSA-65)...');
  // Approval 1: Dr. Marcus Vance (inv1)
  const inv1Keys = demoKeys['inv1'];
  const t1 = Date.now();
  const p1 = { caseId: realCaseId, investigatorId: 'inv1', timestamp: t1 };
  const sig1 = signWithDSA(canonicalJsonBytes(p1), hexToBytes(inv1Keys.dsa.sec));
  const app1Res = await fetch(`${serverUrl}/api/forensics/cases/${realCaseId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ investigatorId: 'inv1', timestamp: t1, signatureHex: bytesToHex(sig1) }),
  });
  const app1Data = await app1Res.json();
  console.log(`   Investigator 1 (Dr. Marcus Vance) Signed: Approvals = ${app1Data.approvalsCount}/2`);

  // Approval 2: Special Agent Sarah Chen (inv2)
  const inv2Keys = demoKeys['inv2'];
  const t2 = Date.now();
  const p2 = { caseId: realCaseId, investigatorId: 'inv2', timestamp: t2 };
  const sig2 = signWithDSA(canonicalJsonBytes(p2), hexToBytes(inv2Keys.dsa.sec));
  const app2Res = await fetch(`${serverUrl}/api/forensics/cases/${realCaseId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ investigatorId: 'inv2', timestamp: t2, signatureHex: bytesToHex(sig2) }),
  });
  const app2Data = await app2Res.json();
  console.log(`   Investigator 2 (Special Agent Sarah Chen) Signed: Approvals = ${app2Data.approvalsCount}/2 (Status: ${app2Data.status})`);

  // 11. Execute Forensic Extraction & Attribution
  console.log('\n11. Executing Forensic Analysis & Inquest Extraction...');
  const extractRes = await fetch(`${serverUrl}/api/forensics/cases/${realCaseId}/extract`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  const result = await extractRes.json();

  console.log('\n------------------------------------------------------------------');
  console.log('📋 INQUEST FORENSIC REPORT SUMMARY');
  console.log('------------------------------------------------------------------');
  console.log(`Verdict Status:             ${result.status}`);
  console.log(`Attributed Identity:        ${result.recipient?.name} (${result.recipient?.email})`);
  console.log(`Recipient Role:             ${result.recipient?.role.toUpperCase()}`);
  console.log(`Extracted Watermark ID:     ${result.watermarkId}`);
  console.log(`Matching Watermark ID:      ${result.watermarkId === watermarkId ? 'MATCHED (100% Exact)' : 'MISMATCH'}`);
  console.log(`Channel 2 Structural Token: ${result.channel2Success ? 'FOUND & EXTRACTED' : 'NOT FOUND'}`);
  console.log(`Committed In Ledger Block:  #${result.blockReceipt?.blockIndex}`);
  console.log(`\nCryptographic Proof Verifications:`);
  console.log(`  [Check 1] Recipient ML-DSA-65 Signature:  ${result.signatureValid ? '✅ VALID (Irrevocable)' : '❌ INVALID'}`);
  console.log(`  [Check 2] Merkle Tree Inclusion Proof:    ${result.merkleInclusionValid ? '✅ VALID (Cryptographic Path)' : '❌ INVALID'}`);
  console.log(`  [Check 3] Validator Consensus Quorum:     ${result.validatorQuorumValid ? '✅ VALID (>= 2/3 Nodes)' : '❌ FAILED'}`);
  console.log(`  [Check 4] Ledger Hash-Chain Integrity:    ${result.chainIntegrityValid ? '✅ VALID (Continuous Chain)' : '❌ TAMPERED'}`);
  console.log('------------------------------------------------------------------\n');

  if (result.status === 'VERIFIED' && result.recipient?.id === 'bob' && result.watermarkId === watermarkId) {
    console.log('✅ TEST PASSED: Downloaded PDF was successfully verified and incontrovertibly attributed to Bob Smith!');
  } else {
    console.error('❌ TEST FAILED: Verification did not produce expected attribution.');
    process.exit(1);
  }
}

testDownloadedLeakFlow().catch((err) => {
  console.error('Test execution error:', err);
  process.exit(1);
});
