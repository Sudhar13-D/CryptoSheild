import fs from 'node:fs';
import path from 'node:path';
import {
  UserRecord,
  EncryptedDocumentPackage,
  DecryptionSession,
  ForensicCase,
  LedgerEngine,
} from '@cryptoshield/shared';

export interface AuditLogEntry {
  id: string;
  timestamp: number;
  actorId: string;
  action: string;
  details: string;
  status: 'SUCCESS' | 'WARN' | 'ERROR';
}

export class ServerStore {
  public readonly dataDir: string;
  public readonly usersFile: string;
  public readonly docsFile: string;
  public readonly k2KeysFile: string;
  public readonly casesFile: string;
  public readonly auditFile: string;
  public readonly leaksDir: string;
  public readonly ledgerEngine: LedgerEngine;

  public activeSessions: Map<string, DecryptionSession> = new Map();
  public usedSessions: Set<string> = new Set();

  constructor(baseDataDir?: string) {
    this.dataDir = baseDataDir || path.join(process.cwd(), 'data');
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }

    this.usersFile = path.join(this.dataDir, 'users.json');
    this.docsFile = path.join(this.dataDir, 'documents.json');
    this.k2KeysFile = path.join(this.dataDir, 'k2_keys.json');
    this.casesFile = path.join(this.dataDir, 'cases.json');
    this.auditFile = path.join(this.dataDir, 'audit_logs.json');
    this.leaksDir = path.join(this.dataDir, 'leaks');

    if (!fs.existsSync(this.leaksDir)) {
      fs.mkdirSync(this.leaksDir, { recursive: true });
    }

    this.ledgerEngine = new LedgerEngine({
      baseDataDir: path.join(this.dataDir, 'ledger'),
    });
  }

  // Users
  public getUsers(): Record<string, UserRecord> {
    if (!fs.existsSync(this.usersFile)) return {};
    try {
      return JSON.parse(fs.readFileSync(this.usersFile, 'utf8'));
    } catch {
      return {};
    }
  }

  public saveUsers(users: Record<string, UserRecord>): void {
    fs.writeFileSync(this.usersFile, JSON.stringify(users, null, 2), 'utf8');
  }

  public getUser(id: string): UserRecord | undefined {
    const users = this.getUsers();
    return users[id];
  }

  public saveUser(user: UserRecord): void {
    const users = this.getUsers();
    users[user.id] = user;
    this.saveUsers(users);
  }

  // Documents
  public getDocuments(): Record<string, EncryptedDocumentPackage> {
    if (!fs.existsSync(this.docsFile)) return {};
    try {
      return JSON.parse(fs.readFileSync(this.docsFile, 'utf8'));
    } catch {
      return {};
    }
  }

  public saveDocuments(docs: Record<string, EncryptedDocumentPackage>): void {
    fs.writeFileSync(this.docsFile, JSON.stringify(docs, null, 2), 'utf8');
  }

  public getDocument(id: string): EncryptedDocumentPackage | undefined {
    const docs = this.getDocuments();
    return docs[id];
  }

  public saveDocument(doc: EncryptedDocumentPackage): void {
    const docs = this.getDocuments();
    docs[doc.docId] = doc;
    this.saveDocuments(docs);
  }

  // Server K2 keys
  public getK2Keys(): Record<string, string> {
    if (!fs.existsSync(this.k2KeysFile)) return {};
    try {
      return JSON.parse(fs.readFileSync(this.k2KeysFile, 'utf8'));
    } catch {
      return {};
    }
  }

  public saveK2Key(docId: string, k2Hex: string): void {
    const keys = this.getK2Keys();
    keys[docId] = k2Hex;
    fs.writeFileSync(this.k2KeysFile, JSON.stringify(keys, null, 2), 'utf8');
  }

  public getK2Key(docId: string): string | undefined {
    const keys = this.getK2Keys();
    return keys[docId];
  }

  // Forensic Cases
  public getCases(): Record<string, ForensicCase> {
    if (!fs.existsSync(this.casesFile)) return {};
    try {
      return JSON.parse(fs.readFileSync(this.casesFile, 'utf8'));
    } catch {
      return {};
    }
  }

  public saveCases(cases: Record<string, ForensicCase>): void {
    fs.writeFileSync(this.casesFile, JSON.stringify(cases, null, 2), 'utf8');
  }

  public getCase(caseId: string): ForensicCase | undefined {
    const cases = this.getCases();
    return cases[caseId];
  }

  public saveCase(c: ForensicCase): void {
    const cases = this.getCases();
    cases[c.caseId] = c;
    this.saveCases(cases);
  }

  // Audit Logs
  public getAuditLogs(): AuditLogEntry[] {
    if (!fs.existsSync(this.auditFile)) return [];
    try {
      return JSON.parse(fs.readFileSync(this.auditFile, 'utf8'));
    } catch {
      return [];
    }
  }

  public addAuditLog(actorId: string, action: string, details: string, status: 'SUCCESS' | 'WARN' | 'ERROR' = 'SUCCESS'): void {
    const logs = this.getAuditLogs();
    const entry: AuditLogEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: Date.now(),
      actorId,
      action,
      details,
      status,
    };
    logs.unshift(entry);
    // Keep max 500 logs
    const trimmed = logs.slice(0, 500);
    fs.writeFileSync(this.auditFile, JSON.stringify(trimmed, null, 2), 'utf8');
  }
}
