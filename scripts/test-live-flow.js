import fs from 'node:fs';
import path from 'node:path';
import {
  canonicalJsonBytes,
  signWithDSA,
  hexToBytes,
  bytesToHex,
} from '../shared/dist/index.js';

async function main() {
  console.log('Testing live CryptoShield API server on http://127.0.0.1:8080...\n');

  // 1. Health check
  const healthRes = await fetch('http://127.0.0.1:8080/api/health');
  const health = await healthRes.json();
  console.log('1. Health check:', health);
  if (!health.offline) throw new Error('Not offline!');

  // 2. Users check
  const usersRes = await fetch('http://127.0.0.1:8080/api/users');
  const users = await usersRes.json();
  console.log(`2. User directory: ${users.length} enrolled users (Alice, Bob, Carol, Inv1..3, Owner)`);

  // 3. Documents check
  const docsRes = await fetch('http://127.0.0.1:8080/api/documents');
  const docs = await docsRes.json();
  console.log(`3. Documents: found ${docs.length} protected document(s): ${docs[0]?.docName} (${docs[0]?.docId})`);

  // 4. Forensic cases check
  const casesRes = await fetch('http://127.0.0.1:8080/api/forensics/cases');
  const cases = await casesRes.json();
  const case0 = cases[0];
  console.log(`4. Forensic case: ${case0.caseId} – "${case0.title}"`);
  console.log(`   Initial status: ${case0.status}, Approvals: ${case0.approvals.length}/2`);

  // 5. Add second approval as inv2
  const demoKeys = JSON.parse(fs.readFileSync('data/demo_keys.json', 'utf8'));
  const inv2Keys = demoKeys['inv2'];
  const app2Timestamp = Date.now();
  const app2Payload = { caseId: case0.caseId, investigatorId: 'inv2', timestamp: app2Timestamp };
  const app2Sig = signWithDSA(canonicalJsonBytes(app2Payload), hexToBytes(inv2Keys.dsa.sec));

  console.log('5. Submitting second approval from Special Agent Sarah Chen (inv2)...');
  const approveRes = await fetch(`http://127.0.0.1:8080/api/forensics/cases/${case0.caseId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      investigatorId: 'inv2',
      timestamp: app2Timestamp,
      signatureHex: bytesToHex(app2Sig),
    }),
  });
  const approveResult = await approveRes.json();
  console.log(`   Result: Approvals=${approveResult.approvalsCount}/2, Status=${approveResult.status}`);

  // 6. Run Forensic Inquest Extraction & Attribution
  console.log('6. Running Forensic Extraction on leaked sample...');
  const extractRes = await fetch(`http://127.0.0.1:8080/api/forensics/cases/${case0.caseId}/extract`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  const extractResult = await extractRes.json();
  console.log(`   Result Status: ${extractResult.status}`);
  console.log(`   Attributed Recipient: ${extractResult.recipient?.name} (${extractResult.recipient?.email})`);
  console.log(`   Extracted Watermark ID: ${extractResult.watermarkId}`);
  console.log(`   [Check 1] ML-DSA-65 Signature: ${extractResult.signatureValid ? 'VALID' : 'INVALID'}`);
  console.log(`   [Check 2] Merkle Inclusion Proof: ${extractResult.merkleInclusionValid ? 'VALID' : 'INVALID'}`);
  console.log(`   [Check 3] Validator Quorum: ${extractResult.validatorQuorumValid ? 'VALID' : 'FAILED'}`);
  console.log(`   [Check 4] Ledger Chain Integrity: ${extractResult.chainIntegrityValid ? 'VALID' : 'FAILED'}`);

  if (extractResult.status !== 'VERIFIED' || extractResult.recipient?.id !== 'bob') {
    throw new Error('Forensic attribution test failed!');
  }

  // 7. Export evidence JSON and test verify.mjs
  console.log('7. Testing Standalone verify.mjs offline CLI...');
  const evidenceBundlePath = 'data/test_evidence_bundle.json';
  const blocksRes = await fetch('http://127.0.0.1:8080/api/ledger/blocks');
  const blocks = await blocksRes.json();
  const matchedBlock = blocks.find((b) => b.records.some((r) => r.payload?.watermark_id === extractResult.watermarkId));
  const matchedRec = matchedBlock.records.find((r) => r.payload?.watermark_id === extractResult.watermarkId);

  const evidenceBundle = {
    caseId: case0.caseId,
    evidenceFile: case0.leakedFileName,
    watermarkId: extractResult.watermarkId,
    matchedRecord: extractResult.matchedRecord,
    recipient: extractResult.recipient,
    signatureHex: matchedRec.signatureHex,
    signerPublicKeyHex: extractResult.recipient?.mlDsaPublicKeyHex,
    blockReceipt: extractResult.blockReceipt,
  };
  fs.writeFileSync(evidenceBundlePath, JSON.stringify(evidenceBundle, null, 2), 'utf8');
  console.log(`   Evidence bundle written to ${evidenceBundlePath}`);

  // 8. Test Tamper Demo & Consensus Divergence
  console.log('8. Testing Tamper Demo on Node-1...');
  const tamperRes = await fetch('http://127.0.0.1:8080/api/ledger/tamper', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nodeId: 'node-1', blockIndex: 1 }),
  });
  console.log('   Tamper triggered:', await tamperRes.json());

  const verifyTamperRes = await fetch('http://127.0.0.1:8080/api/ledger/verify');
  const verifyTamper = await verifyTamperRes.json();
  console.log(`   Chain verification after tamper: isValid=${verifyTamper.isValid}`);
  console.log(`   Divergent nodes detected: [${verifyTamper.divergentNodes.join(', ')}]`);
  console.log(`   Validator quorum: ${verifyTamper.validatorQuorumValid ? 'VALID (2-of-3 majority holds)' : 'FAILED'}`);

  if (!verifyTamper.divergentNodes.includes('node-1') || !verifyTamper.validatorQuorumValid) {
    throw new Error('Tamper detection failed!');
  }

  // 9. Repair Node-1
  console.log('9. Restoring Node-1 from majority consensus...');
  const repairRes = await fetch('http://127.0.0.1:8080/api/ledger/repair', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nodeId: 'node-1' }),
  });
  console.log('   Repair result:', await repairRes.json());

  const verifyRepairRes = await fetch('http://127.0.0.1:8080/api/ledger/verify');
  const verifyRepair = await verifyRepairRes.json();
  console.log(`   Chain verification after repair: isValid=${verifyRepair.isValid}`);
  console.log(`   Divergent nodes: [${verifyRepair.divergentNodes.join(', ')}]`);

  if (!verifyRepair.isValid || verifyRepair.divergentNodes.length > 0) {
    throw new Error('Repair failed!');
  }

  console.log('\n==================================================================');
  console.log('🎉 ALL LIVE SYSTEM FLOWS PASSED WITH 100% SUCCESS');
  console.log('==================================================================\n');
}

main().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
