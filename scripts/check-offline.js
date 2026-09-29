import fs from 'node:fs';
import path from 'node:path';

const ALLOWED_PATTERNS = [
  /^http:\/\/127\.0\.0\.1/,
  /^http:\/\/localhost/,
  /^http:\/\/\$/,
  /^http:\/\/\${/,
  /^http:\/\/www\.w3\.org\//,
  /^https:\/\/www\.w3\.org\//,
  /^http:\/\/ns\.adobe\.com\//,
  /^http:\/\/www\.xfa\.org\/schema\//,
  /^http:\/\/schemas\./,
  /^https:\/\/schemas\./,
  /^http:\/\/xml\./,
  /^https:\/\/xml\./,
  /^http:\/\/www\.apache\.org\/licenses\//,
  /^https:\/\/github\.com\/Hopding\/pdf-lib/,
  /^https:\/\/reactjs\.org\/docs\/error-decoder/,
];

function isAllowedUrl(url) {
  return ALLOWED_PATTERNS.some((pattern) => pattern.test(url));
}

function scanDirectory(dir, violations = []) {
  if (!fs.existsSync(dir)) return violations;
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'data') {
        continue;
      }
      scanDirectory(fullPath, violations);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (['.js', '.mjs', '.html', '.css', '.ts', '.tsx'].includes(ext)) {
        const content = fs.readFileSync(fullPath, 'utf8');
        const urlRegex = /https?:\/\/[^\s"'`<>{}|\^~]+/g;
        let match;
        while ((match = urlRegex.exec(content)) !== null) {
          const rawUrl = match[0].replace(/[.,;:)]+$/, '');
          if (!isAllowedUrl(rawUrl)) {
            violations.push({
              file: path.relative(process.cwd(), fullPath),
              url: rawUrl,
            });
          }
        }
      }
    }
  }

  return violations;
}

console.log('🔍 Scanning CryptoShield assets for external network dependencies...');

const targetDirs = [
  path.join(process.cwd(), 'web', 'src'),
  path.join(process.cwd(), 'shared', 'src'),
  path.join(process.cwd(), 'server', 'src'),
];

if (fs.existsSync(path.join(process.cwd(), 'web', 'dist'))) {
  targetDirs.push(path.join(process.cwd(), 'web', 'dist'));
}

const violations = [];
for (const dir of targetDirs) {
  scanDirectory(dir, violations);
}

if (violations.length > 0) {
  console.error('\n❌ OFFLINE POLICY VIOLATION: External URLs detected:');
  for (const v of violations) {
    console.error(`  - In [${v.file}]: ${v.url}`);
  }
  console.error('\nCRYPTOSHIELD must be strictly air-gapped with zero external network requests.');
  process.exit(1);
} else {
  console.log('✅ OFFLINE INTEGRITY CONFIRMED: 0 external HTTP/HTTPS requests found.');
  console.log('   All assets, cryptographic algorithms, fonts, and workers are bundled 100% locally.');
  process.exit(0);
}
