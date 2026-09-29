import fs from 'node:fs';
import path from 'node:path';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import {
  generateKeyPairKEM,
  generateKeyPairDSA,
  bytesToHex,
  hexToBytes,
  splitKey,
  combineKey,
  encryptAesGcm,
  decryptAesGcm,
  wrapKeyWithKEM,
  unwrapKeyWithKEM,
  createLedgerRecord,
  signWithDSA,
  canonicalJsonBytes,
  canonicalJsonStringify,
  sha3_256Hex,
  embedChannel2,
  embedWatermark,
  EncryptedDocumentPackage,
  UserRecord,
} from '@cryptoshield/shared';
import { ServerStore } from './store.js';

export async function createSamplePdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const fontBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const fontRegular = await doc.embedFont(StandardFonts.Helvetica);

  // Helper for pages
  const addPageContent = (pageNum: number, title: string, content: string[]) => {
    const page = doc.addPage([595.28, 841.89]); // A4
    const { width, height } = page.getSize();

    // Classification banner
    page.drawRectangle({
      x: 0,
      y: height - 35,
      width,
      height: 35,
      color: rgb(0.85, 0.1, 0.1),
    });
    page.drawText('TOP SECRET // CRYPTOSHIELD FORENSIC PROVENANCE DIRECTIVE', {
      x: 50,
      y: height - 23,
      size: 11,
      font: fontBold,
      color: rgb(1, 1, 1),
    });

    // Header
    page.drawText(title, {
      x: 50,
      y: height - 80,
      size: 16,
      font: fontBold,
      color: rgb(0.1, 0.15, 0.3),
    });

    page.drawLine({
      start: { x: 50, y: height - 90 },
      end: { x: width - 50, y: height - 90 },
      thickness: 1.5,
      color: rgb(0.2, 0.3, 0.6),
    });

    let yOffset = height - 120;
    for (const paragraph of content) {
      page.drawText(paragraph, {
        x: 50,
        y: yOffset,
        size: 10,
        font: fontRegular,
        color: rgb(0.2, 0.2, 0.2),
        lineHeight: 14,
        maxWidth: width - 100,
      });
      yOffset -= 45;
    }

    // Footer
    page.drawText(`Page ${pageNum} of 3 // SIH 2026 PS 26237 // Offline Air-Gapped Verification`, {
      x: 50,
      y: 30,
      size: 9,
      font: fontRegular,
      color: rgb(0.5, 0.5, 0.5),
    });
  };

  addPageContent(1, 'SECTION 1: QUANTUM-RESILIENT ACCESS PROTOCOL', [
    '1.1 Purpose: This operational document establishes binding cryptographic controls for classified information provenance using National Institute of Standards and Technology (NIST) FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).',
    '1.2 Trust Architecture: Secret cryptographic material remains strictly confined within authorized recipient browser enclaves. Zero key exposure or plaintext transmission occurs across server boundary components.',
    '1.3 Dual-Key Secret Sharing: Plaintext PDF assets are symmetrically locked under AES-256-GCM file keys (K) generated dynamically. The file key is divided into K1 (held in the encrypted distribution bundle) and K2 (governed by the immutable consensus key release arbiter).',
  ]);

  addPageContent(2, 'SECTION 2: COMMIT-BEFORE-RELEASE LEDGER PROVENANCE', [
    '2.1 Provenance Gate: A recipient cannot obtain key share K2 without executing an irrevocable, ML-DSA-65 signed decryption provenance record containing unique session tokens and client nonces.',
    '2.2 Consensus Validation: A three-node permissioned ledger independently verifies all recipient signatures and cryptographic parameters, requiring a 2-of-3 quorum before stamping block inclusion.',
    '2.3 Forensic Watermark ID: The recipient browser computes a 96-bit cryptographic watermark identifier bound to doc_id, recipient_id, session_id, and mutual nonces, permanently anchored into the distributed ledger.',
  ]);

  addPageContent(3, 'SECTION 3: FORENSIC ATTRIBUTION & INVESTIGATION DISCLOSURE', [
    '3.1 Dual-Channel Watermarking: Plaintext pages are transformed using 8x8 block discrete cosine transform (DCT) differential luminance modulation alongside structural XMP/invisible-text tokens.',
    '3.2 Multi-Investigator Quorum: In accordance with chain-of-custody statutory requirements, forensic case extraction requires a minimum of two authorized investigator signatures before attribution data can be unlocked.',
    '3.3 Tamper Evident Guarantee: Any retroactive alteration of provenance blocks triggers instant consensus divergence, maintaining incontrovertible evidence of legitimate recipient access.',
  ]);

  return await doc.save();
}

export async function seedDemoData(store: ServerStore): Promise<void> {
  const demoKeysFile = path.join(store.dataDir, 'demo_keys.json');
  console.log('[Seed] Initializing CryptoShield demo environment...');

  // 1. Generate or load user keys
  const demoUsers = [
    { id: 'owner@org', name: 'Document Custodian (Owner)', role: 'owner' as const, email: 'owner@defense.gov' },
    { id: 'alice', name: 'Alice Johnson (Research Analyst)', role: 'recipient' as const, email: 'alice@defense.gov' },
    { id: 'bob', name: 'Bob Smith (Field Operative)', role: 'recipient' as const, email: 'bob@defense.gov' },
    { id: 'carol', name: 'Carol Davis (Systems Engineer)', role: 'recipient' as const, email: 'carol@defense.gov' },
    { id: 'inv1', name: 'Dr. Marcus Vance', role: 'investigator' as const, email: 'vance@forensics.gov' },
    { id: 'inv2', name: 'Special Agent Sarah Chen', role: 'investigator' as const, email: 'chen@forensics.gov' },
    { id: 'inv3', name: 'Inspector David Ross', role: 'investigator' as const, email: 'ross@forensics.gov' },
  ];

  const keysMap: Record<string, { kem: { pub: string; sec: string }; dsa: { pub: string; sec: string } }> = {};

  for (const u of demoUsers) {
    const kem = generateKeyPairKEM();
    const dsa = generateKeyPairDSA();

    keysMap[u.id] = {
      kem: { pub: bytesToHex(kem.publicKey), sec: bytesToHex(kem.secretKey) },
      dsa: { pub: bytesToHex(dsa.publicKey), sec: bytesToHex(dsa.secretKey) },
    };

    const userRecord: UserRecord = {
      id: u.id,
      name: u.name,
      role: u.role,
      email: u.email,
      mlKemPublicKeyHex: keysMap[u.id].kem.pub,
      mlDsaPublicKeyHex: keysMap[u.id].dsa.pub,
      enrolledAt: Date.now() - 3600000,
    };

    store.saveUser(userRecord);

    // Commit enrollment to ledger
    const proofPayload = { id: u.id, name: u.name, role: u.role, email: u.email, mlKem: keysMap[u.id].kem.pub, mlDsa: keysMap[u.id].dsa.pub };
    const proofBytes = canonicalJsonBytes(proofPayload);
    const signature = signWithDSA(proofBytes, dsa.secretKey);

    const record = createLedgerRecord(
      `enroll-${u.id}`,
      'USER_REGISTRATION',
      proofPayload,
      u.id,
      dsa.secretKey,
      dsa.publicKey,
      userRecord.enrolledAt
    );
    record.signatureHex = bytesToHex(signature);

    await store.ledgerEngine.commitRecord(record, store.getUsers());
  }

  // Save private keys for demo login / browser auto-fill
  fs.writeFileSync(demoKeysFile, JSON.stringify(keysMap, null, 2), 'utf8');

  // 2. Generate and encrypt sample 3-page PDF
  console.log('[Seed] Generating classified 3-page sample PDF...');
  const samplePdfBytes = await createSamplePdf();
  const docHash = sha3_256Hex(samplePdfBytes);
  const docId = 'DOC-AEGIS-2026-001';
  const docName = 'Project_Aegis_Quantum_Directive.pdf';

  // Generate 32-byte key K
  const K = crypto.getRandomValues(new Uint8Array(32));
  const { k1, k2 } = splitKey(K);

  // Encrypt PDF with AES-256-GCM under K
  const { ciphertext, iv } = await encryptAesGcm(K, samplePdfBytes);

  // Wrap K1 for alice, bob, carol
  const recipients: EncryptedDocumentPackage['recipients'] = {};
  const authorizedRecipients = ['alice', 'bob', 'carol'];

  for (const rid of authorizedRecipients) {
    const userKemPub = hexToBytes(keysMap[rid].kem.pub);
    const wrapped = await wrapKeyWithKEM(userKemPub, k1);
    recipients[rid] = {
      recipientId: rid,
      kemCiphertextHex: bytesToHex(wrapped.kemCiphertext),
      wrappedK1Hex: bytesToHex(wrapped.wrappedKey),
      wrapIvHex: bytesToHex(wrapped.iv),
    };
  }

  const docPackage: EncryptedDocumentPackage = {
    docId,
    docName,
    docHash,
    fileSize: samplePdfBytes.length,
    pageCount: 3,
    ownerId: 'owner@org',
    createdAt: Date.now() - 1800000,
    ciphertextHex: bytesToHex(ciphertext),
    ivHex: bytesToHex(iv),
    recipients,
  };

  store.saveDocument(docPackage);
  store.saveK2Key(docId, bytesToHex(k2));

  // 3. Simulate real decryption flow for alice, bob, carol
  console.log('[Seed] Simulating commit-before-release decryption for authorized recipients...');
  let bobWatermarkedPdf: Uint8Array | null = null;
  let bobWatermarkId: string = '';

  for (const rid of authorizedRecipients) {
    const sessionId = `seed-sess-${rid}`;
    const serverNonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const clientNonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));

    // Compute watermark_id = first 12 bytes of sha3_256(canonical(doc_id, recipient_id, session_id, server_nonce, client_nonce))
    const canon = canonicalJsonStringify({
      client_nonce: clientNonce,
      doc_id: docId,
      recipient_id: rid,
      server_nonce: serverNonce,
      session_id: sessionId,
    });
    const watermarkId = sha3_256Hex(canon).substring(0, 24);

    const decRecord = {
      doc_id: docId,
      doc_hash: docHash,
      recipient_id: rid,
      session_id: sessionId,
      watermark_id: watermarkId,
      server_nonce: serverNonce,
      client_nonce: clientNonce,
      timestamp: Date.now() - (rid === 'bob' ? 600000 : 900000),
      alg: 'ML-DSA-65' as const,
    };

    const dsaSec = hexToBytes(keysMap[rid].dsa.sec);
    const dsaPub = hexToBytes(keysMap[rid].dsa.pub);
    const sig = signWithDSA(canonicalJsonBytes(decRecord), dsaSec);

    const ledgerRecord = createLedgerRecord(
      `seed-prov-${docId}-${rid}`,
      'DECRYPTION_PROVENANCE',
      decRecord as unknown as Record<string, unknown>,
      rid,
      dsaSec,
      dsaPub,
      decRecord.timestamp
    );
    ledgerRecord.signatureHex = bytesToHex(sig);

    // Commit to ledger
    await store.ledgerEngine.commitRecord(ledgerRecord, store.getUsers());

    // Watermark PDF for this recipient
    const watermarkedPdf = await embedChannel2(samplePdfBytes, watermarkId);

    if (rid === 'bob') {
      bobWatermarkedPdf = watermarkedPdf;
      bobWatermarkId = watermarkId;
    }
  }

  // 4. Save downloadable "leaked_sample_bob.pdf"
  if (bobWatermarkedPdf) {
    const leakFilePath = path.join(store.leaksDir, 'leaked_sample_bob.pdf');
    fs.writeFileSync(leakFilePath, Buffer.from(bobWatermarkedPdf));
    console.log(`[Seed] Downloadable leak file saved: ${leakFilePath} (Watermark: ${bobWatermarkId})`);

    // 5. Seed default forensic investigation case for Bob's leak
    const caseId = 'CASE-2026-001';
    const inv1DsaSec = hexToBytes(keysMap['inv1'].dsa.sec);
    const approvalPayload = { caseId, investigatorId: 'inv1', timestamp: Date.now() - 300000 };
    const approvalSig = signWithDSA(canonicalJsonBytes(approvalPayload), inv1DsaSec);

    const defaultCase = {
      caseId,
      title: 'Forensic Inquest: Intercepted Aegis Directive Leak',
      leakedFileName: 'leaked_sample_bob.pdf',
      uploadedAt: Date.now() - 400000,
      investigatorId: 'inv1',
      fileDataHex: bytesToHex(bobWatermarkedPdf),
      approvals: [
        {
          caseId,
          investigatorId: 'inv1',
          approvedAt: approvalPayload.timestamp,
          signatureHex: bytesToHex(approvalSig),
        },
      ],
      status: 'PENDING_APPROVAL' as const, // 1/2 approvals: requires 1 more approval from inv2 or inv3!
    };

    store.saveCase(defaultCase);
    console.log('[Seed] Created default forensic case CASE-2026-001 (1/2 approvals recorded, ready for inv2/inv3 approval demo)');
  }

  console.log('[Seed] Database seeding completed successfully.');
}
