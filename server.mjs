import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3070;

const indexHtml = readFileSync(join(__dirname, 'index.html'), 'utf-8');

const server = createServer((req, res) => {
  // Health check
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'proof.rootz.global', version: '1.0.0' }));
    return;
  }

  // Serve index.html for everything else (single page site)
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'public, max-age=3600',
  });
  res.end(indexHtml);
});

server.listen(PORT, () => {
  console.log(`proof.rootz.global running on port ${PORT}`);
});
