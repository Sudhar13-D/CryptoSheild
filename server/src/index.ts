import { ServerStore } from './store.js';
import { createApp } from './app.js';
import { seedDemoData } from './seed.js';

const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = '127.0.0.1';

async function main() {
  const store = new ServerStore();

  // If users or documents are empty, seed demo data automatically on first run
  const users = store.getUsers();
  if (Object.keys(users).length === 0) {
    console.log('[CryptoShield] First run detected. Seeding demo environment...');
    await seedDemoData(store);
  }

  const app = createApp(store);

  app.listen(PORT, HOST, () => {
    console.log(`==================================================================`);
    console.log(`🛡️  CRYPTOSHIELD – Forensic Verification System running`);
    console.log(`📍 Endpoint: http://127.0.0.1:${PORT}`);
    console.log(`🔒 Mode: FULLY OFFLINE (Zero external network requests)`);
    console.log(`==================================================================`);
  });
}

main().catch((err) => {
  console.error('[Fatal Error] Failed to start server:', err);
  process.exit(1);
});
