import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3070;

const indexHtml = readFileSync(join(__dirname, 'index.html'), 'utf-8');
const techHtml = readFileSync(join(__dirname, 'tech.html'), 'utf-8');
const tourHtml = readFileSync(join(__dirname, 'tour.html'), 'utf-8');
const wellKnownAi = readFileSync(join(__dirname, 'well-known-ai.json'), 'utf-8');
const sitemapXml = readFileSync(join(__dirname, 'sitemap.xml'), 'utf-8');
const llmsTxt = readFileSync(join(__dirname, 'llms.txt'), 'utf-8');
const knowledgeJson = readFileSync(join(__dirname, 'knowledge.json'), 'utf-8');
const feedJson = readFileSync(join(__dirname, 'feed.json'), 'utf-8');

const server = createServer((req, res) => {
  // AI Discovery Standard
  if (req.url === '/.well-known/ai' || req.url === '/.well-known/ai/') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600',
    });
    res.end(wellKnownAi);
    return;
  }

  // Knowledge base (Tier 2)
  if (req.url === '/.well-known/ai/knowledge' || req.url === '/.well-known/ai/knowledge/') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600',
    });
    res.end(knowledgeJson);
    return;
  }

  // AI Feed (Tier 3)
  if (req.url === '/.well-known/ai/feed' || req.url === '/.well-known/ai/feed/') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600',
    });
    res.end(feedJson);
    return;
  }

  // Sitemap
  if (req.url === '/sitemap.xml') {
    res.writeHead(200, { 'Content-Type': 'application/xml', 'Cache-Control': 'public, max-age=86400' });
    res.end(sitemapXml);
    return;
  }

  // LLMs.txt
  if (req.url === '/llms.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
    res.end(llmsTxt);
    return;
  }

  // Robots.txt
  if (req.url === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('User-agent: *\nAllow: /\nSitemap: https://proof.rootz.global/sitemap.xml\n');
    return;
  }

  // Tech page
  if (req.url === '/tech' || req.url === '/tech/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
    res.end(techHtml);
    return;
  }

  // Tour page
  if (req.url === '/tour' || req.url === '/tour/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
    res.end(tourHtml);
    return;
  }

  // Health check
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'proof.rootz.global', version: '1.1.0' }));
    return;
  }

  // Serve index.html for everything else
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'public, max-age=3600',
  });
  res.end(indexHtml);
});

server.listen(PORT, () => {
  console.log(`proof.rootz.global running on port ${PORT}`);
});
