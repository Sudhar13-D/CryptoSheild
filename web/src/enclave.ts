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
  signWithDSA,
  canonicalJsonBytes,
  canonicalJsonStringify,
  sha3_256Hex,
  embedChannel2,
  embedWatermark,
  EncryptedDocumentPackage,
  DecryptionRecord,
  SignedDecryptionRecord,
  KeyReleaseResponse,
  UserRecord,
} from '@cryptoshield/shared';
import * as pdfjsLib from 'pdfjs-dist';
import { PDFDocument } from 'pdf-lib';

// Set up local bundled worker for pdfjs-dist
pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdf.worker.min.mjs';

export interface EnclaveKeyPair {
  kem: {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
    publicKeyHex: string;
    secretKeyHex: string;
  };
  dsa: {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
    publicKeyHex: string;
    secretKeyHex: string;
  };
}

/**
 * Generates fresh PQC ML-KEM-768 and ML-DSA-65 keypairs inside the browser boundary
 */
export function generateEnclaveKeyPairs(): EnclaveKeyPair {
  const kem = generateKeyPairKEM();
  const dsa = generateKeyPairDSA();

  return {
    kem: {
      publicKey: kem.publicKey,
      secretKey: kem.secretKey,
      publicKeyHex: bytesToHex(kem.publicKey),
      secretKeyHex: bytesToHex(kem.secretKey),
    },
    dsa: {
      publicKey: dsa.publicKey,
      secretKey: dsa.secretKey,
      publicKeyHex: bytesToHex(dsa.publicKey),
      secretKeyHex: bytesToHex(dsa.secretKey),
    },
  };
}

/**
 * Client-Side Encryption Flow (Owner):
 * Plaintext and raw K never leave the browser. K2 is given to server key-release arbiter.
 */
export async function encryptAndPackageDocument(
  pdfBytes: Uint8Array,
  docName: string,
  ownerId: string,
  authorizedRecipients: UserRecord[]
): Promise<{ docPackage: EncryptedDocumentPackage; k2Hex: string }> {
  const docHash = sha3_256Hex(pdfBytes);
  const docId = `DOC-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;

  // 1. Generate random file key K (32 bytes)
  const K = crypto.getRandomValues(new Uint8Array(32));

  // 2. Split K = K1 XOR K2
  const { k1, k2 } = splitKey(K);

  // 3. Encrypt PDF with AES-256-GCM under K
  const { ciphertext, iv } = await encryptAesGcm(K, pdfBytes);

  // 4. Wrap K1 for each authorized recipient via ML-KEM-768
  const recipientsMap: EncryptedDocumentPackage['recipients'] = {};
  for (const recipient of authorizedRecipients) {
    const userKemPubKey = hexToBytes(recipient.mlKemPublicKeyHex);
    const wrapped = await wrapKeyWithKEM(userKemPubKey, k1);
    recipientsMap[recipient.id] = {
      recipientId: recipient.id,
      kemCiphertextHex: bytesToHex(wrapped.kemCiphertext),
      wrappedK1Hex: bytesToHex(wrapped.wrappedKey),
      wrapIvHex: bytesToHex(wrapped.iv),
    };
  }

  // Count pages using pdf-lib
  const pdfDoc = await PDFDocument.load(pdfBytes);
  const pageCount = pdfDoc.getPageCount();

  const docPackage: EncryptedDocumentPackage = {
    docId,
    docName,
    docHash,
    fileSize: pdfBytes.length,
    pageCount,
    ownerId,
    createdAt: Date.now(),
    ciphertextHex: bytesToHex(ciphertext),
    ivHex: bytesToHex(iv),
    recipients: recipientsMap,
  };

  return {
    docPackage,
    k2Hex: bytesToHex(k2),
  };
}

export type DecryptProgressCallback = (step: number, title: string, desc: string) => void;

/**
 * Recipient Live Decryption & Watermarking Stepper (in browser enclave)
 */
export async function decryptAndWatermarkDocument(
  docPackage: EncryptedDocumentPackage,
  recipientId: string,
  userKeys: EnclaveKeyPair,
  onProgress?: DecryptProgressCallback
): Promise<{ watermarkedPdfBytes: Uint8Array; watermarkId: string; blockIndex: number }> {
  // Check recipient authorization
  const recipientWrap = docPackage.recipients[recipientId];
  if (!recipientWrap) {
    throw new Error('You are not authorized to decrypt this document.');
  }

  // Step 1: Unwrap K1 via ML-KEM-768
  onProgress?.(1, 'Unwrapping K1 Share', 'Decapsulating ML-KEM-768 shared secret in browser enclave...');
  const k1 = await unwrapKeyWithKEM(
    userKeys.kem.secretKey,
    hexToBytes(recipientWrap.kemCiphertextHex),
    hexToBytes(recipientWrap.wrappedK1Hex),
    hexToBytes(recipientWrap.wrapIvHex)
  );

  // Step 2: Request Decryption Session & Server Nonce
  onProgress?.(2, 'Requesting Decryption Session', 'Negotiating server nonce and anti-replay session token...');
  const sessionRes = await fetch('/api/decrypt/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-actor-id': recipientId },
    body: JSON.stringify({ docId: docPackage.docId, recipientId }),
  });
  if (!sessionRes.ok) {
    const err = await sessionRes.json();
    throw new Error(err.error || 'Failed to initiate decryption session');
  }
  const { sessionId, serverNonce } = await sessionRes.json();

  // Step 3: Compute Cryptographic Watermark ID & Client Nonce
  onProgress?.(3, 'Computing Forensic Watermark Binding', 'Binding doc_id, recipient_id, session_id, and mutual nonces...');
  const clientNonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const canonBinding = canonicalJsonStringify({
    client_nonce: clientNonce,
    doc_id: docPackage.docId,
    recipient_id: recipientId,
    server_nonce: serverNonce,
    session_id: sessionId,
  });
  const watermarkId = sha3_256Hex(canonBinding).substring(0, 24);

  // Step 4: Construct and ML-DSA-65 Sign Decryption Provenance Record
  onProgress?.(4, 'Signing Decryption Record (ML-DSA-65)', 'Signing irrevocable provenance record with recipient secret key...');
  const decRecord: DecryptionRecord = {
    doc_id: docPackage.docId,
    doc_hash: docPackage.docHash,
    recipient_id: recipientId,
    session_id: sessionId,
    watermark_id: watermarkId,
    server_nonce: serverNonce,
    client_nonce: clientNonce,
    timestamp: Date.now(),
    alg: 'ML-DSA-65',
  };

  const payloadBytes = canonicalJsonBytes(decRecord);
  const signatureBytes = signWithDSA(payloadBytes, userKeys.dsa.secretKey);
  const signedRecord: SignedDecryptionRecord = {
    record: decRecord,
    signatureHex: bytesToHex(signatureBytes),
    recipientPublicKeyHex: userKeys.dsa.publicKeyHex,
  };

  // Step 5: Commit to 3-Validator Ledger & Release K2 (COMMIT-BEFORE-RELEASE)
  onProgress?.(5, 'Ledger Consensus & Key Release', 'Committing signed record to 3-validator ledger; receiving wrapped K2...');
  const releaseRes = await fetch('/api/decrypt/commit-and-release', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-actor-id': recipientId },
    body: JSON.stringify({
      docId: docPackage.docId,
      recipientId,
      signedRecord,
    }),
  });

  if (!releaseRes.ok) {
    const err = await releaseRes.json();
    throw new Error(err.error || 'Commit-before-release protocol failed');
  }

  const releaseData: KeyReleaseResponse = await releaseRes.json();

  // Step 6: Unwrap K2 via ML-KEM-768
  onProgress?.(6, 'Unwrapping K2 Share', 'Decapsulating server-released K2 key share in browser...');
  const k2 = await unwrapKeyWithKEM(
    userKeys.kem.secretKey,
    hexToBytes(releaseData.kemCiphertextHex),
    hexToBytes(releaseData.wrappedK2Hex),
    hexToBytes(releaseData.wrapIvHex)
  );

  // Step 7: Combine K = K1 XOR K2 and Decrypt Plaintext PDF
  onProgress?.(7, 'Reconstructing File Key K & AES-256-GCM Decryption', 'Recombining K1 XOR K2 to unlock plaintext PDF in browser memory...');
  const K = combineKey(k1, k2);
  const plaintextPdf = await decryptAesGcm(
    K,
    hexToBytes(docPackage.ciphertextHex),
    hexToBytes(docPackage.ivHex)
  );

  // Step 8: Client-Side Dual-Channel Watermarking
  onProgress?.(8, 'Forensic Watermark Embedding', 'Embedding Channel 1 (8x8 Block DCT luminance) and Channel 2 (Metadata/Invisible Token)...');
  // First apply Channel 2 structural watermark
  const ch2Pdf = await embedChannel2(plaintextPdf, watermarkId);

  // Next render pages with pdfjs to canvas and embed Channel 1 DCT watermark on raster pages
  const loadingTask = pdfjsLib.getDocument({ data: ch2Pdf });
  const pdfDocProxy = await loadingTask.promise;
  const numPages = pdfDocProxy.numPages;

  const outDoc = await PDFDocument.create();

  for (let pageNum = 1; pageNum <= numPages; pageNum++) {
    const page = await pdfDocProxy.getPage(pageNum);
    const viewport = page.getViewport({ scale: 2.0 }); // ~150 DPI

    // Render to offscreen canvas
    const canvas = document.createElement('canvas');
    canvas.width = viewport.width;
    canvas.height = viewport.height;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('Failed to acquire canvas context');

    await page.render({
      canvasContext: ctx,
      viewport,
    }).promise;

    // Get pixel data
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    // Embed Channel 1 DCT watermark into pixel buffer
    embedWatermark(imgData.data, canvas.width, canvas.height, watermarkId, docPackage.docHash);

    // Put modified pixels back
    ctx.putImageData(imgData, 0, 0);

    // Convert canvas to lossless PNG bytes and embed into output PDF
    const dataUrl = canvas.toDataURL('image/png');
    const base64Data = dataUrl.split(',')[1];
    const binaryStr = atob(base64Data);
    const imageBytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      imageBytes[i] = binaryStr.charCodeAt(i);
    }

    const embeddedImage = await outDoc.embedPng(imageBytes);
    const newPage = outDoc.addPage([viewport.width / 2.0, viewport.height / 2.0]);
    newPage.drawImage(embeddedImage, {
      x: 0,
      y: 0,
      width: viewport.width / 2.0,
      height: viewport.height / 2.0,
    });
  }

  // Add Channel 2 to final rasterized PDF
  const intermediateBytes = await outDoc.save();
  const finalWatermarkedPdf = await embedChannel2(intermediateBytes, watermarkId);

  onProgress?.(9, 'Watermarked Document Ready', 'Generated forensic attributed PDF. Ready for air-gapped viewing.');

  return {
    watermarkedPdfBytes: finalWatermarkedPdf,
    watermarkId,
    blockIndex: releaseData.blockReceipt.blockIndex,
  };
}
