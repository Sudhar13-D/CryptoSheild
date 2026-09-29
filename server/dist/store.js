import fs from 'node:fs';
import path from 'node:path';
import { LedgerEngine, } from '@cryptoshield/shared';
export class ServerStore {
    dataDir;
    usersFile;
    docsFile;
    k2KeysFile;
    casesFile;
    auditFile;
    leaksDir;
    ledgerEngine;
    activeSessions = new Map();
    usedSessions = new Set();
    constructor(baseDataDir) {
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
    getUsers() {
        if (!fs.existsSync(this.usersFile))
            return {};
        try {
            return JSON.parse(fs.readFileSync(this.usersFile, 'utf8'));
        }
        catch {
            return {};
        }
    }
    saveUsers(users) {
        fs.writeFileSync(this.usersFile, JSON.stringify(users, null, 2), 'utf8');
    }
    getUser(id) {
        const users = this.getUsers();
        return users[id];
    }
    saveUser(user) {
        const users = this.getUsers();
        users[user.id] = user;
        this.saveUsers(users);
    }
    // Documents
    getDocuments() {
        if (!fs.existsSync(this.docsFile))
            return {};
        try {
            return JSON.parse(fs.readFileSync(this.docsFile, 'utf8'));
        }
        catch {
            return {};
        }
    }
    saveDocuments(docs) {
        fs.writeFileSync(this.docsFile, JSON.stringify(docs, null, 2), 'utf8');
    }
    getDocument(id) {
        const docs = this.getDocuments();
        return docs[id];
    }
    saveDocument(doc) {
        const docs = this.getDocuments();
        docs[doc.docId] = doc;
        this.saveDocuments(docs);
    }
    // Server K2 keys
    getK2Keys() {
        if (!fs.existsSync(this.k2KeysFile))
            return {};
        try {
            return JSON.parse(fs.readFileSync(this.k2KeysFile, 'utf8'));
        }
        catch {
            return {};
        }
    }
    saveK2Key(docId, k2Hex) {
        const keys = this.getK2Keys();
        keys[docId] = k2Hex;
        fs.writeFileSync(this.k2KeysFile, JSON.stringify(keys, null, 2), 'utf8');
    }
    getK2Key(docId) {
        const keys = this.getK2Keys();
        return keys[docId];
    }
    // Forensic Cases
    getCases() {
        if (!fs.existsSync(this.casesFile))
            return {};
        try {
            return JSON.parse(fs.readFileSync(this.casesFile, 'utf8'));
        }
        catch {
            return {};
        }
    }
    saveCases(cases) {
        fs.writeFileSync(this.casesFile, JSON.stringify(cases, null, 2), 'utf8');
    }
    getCase(caseId) {
        const cases = this.getCases();
        return cases[caseId];
    }
    saveCase(c) {
        const cases = this.getCases();
        cases[c.caseId] = c;
        this.saveCases(cases);
    }
    // Audit Logs
    getAuditLogs() {
        if (!fs.existsSync(this.auditFile))
            return [];
        try {
            return JSON.parse(fs.readFileSync(this.auditFile, 'utf8'));
        }
        catch {
            return [];
        }
    }
    addAuditLog(actorId, action, details, status = 'SUCCESS') {
        const logs = this.getAuditLogs();
        const entry = {
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
