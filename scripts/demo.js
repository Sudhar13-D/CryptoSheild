import { execSync, spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';

console.log('==================================================================');
console.log('🚀 CRYPTOSHIELD – Building & Launching Offline Demo Environment');
console.log('==================================================================\n');

// 1. Build all packages
console.log('[1/3] Building packages (@cryptoshield/shared, server, web)...');
execSync('npm run build', { stdio: 'inherit' });

// 2. Launch server
console.log('\n[2/3] Starting server on http://127.0.0.1:8080...');
const serverProcess = spawn('node', ['server/dist/index.js'], {
  stdio: 'inherit',
  env: { ...process.env, PORT: '8080' },
});

serverProcess.on('error', (err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

process.on('SIGINT', () => {
  console.log('\nStopping CryptoShield...');
  serverProcess.kill();
  process.exit(0);
});

process.on('SIGTERM', () => {
  serverProcess.kill();
  process.exit(0);
});
