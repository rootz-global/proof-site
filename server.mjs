import { createServer } from 'node:http';
import { readFileSync, appendFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3070;
const HITS_LOG = join(__dirname, 'hits.jsonl');

// Load static files
const loadFile = (name) => {
  const path = join(__dirname, name);
  return existsSync(path) ? readFileSync(path, 'utf-8') : null;
};

const indexHtml = loadFile('index.html');
const techHtml = loadFile('tech.html');
const tourHtml = loadFile('tour.html');
const routerTourHtml = loadFile('router-tour.html');
const complianceHtml = loadFile('compliance.html');
const wellKnownAi = loadFile('well-known-ai.json');
const sitemapXml = loadFile('sitemap.xml');
const llmsTxt = loadFile('llms.txt');
const knowledgeJson = loadFile('knowledge.json');
const feedJson = loadFile('feed.json');

// --- Analytics: simple hit logging ---

function logHit(req, page, extra) {
  const entry = {
    ts: new Date().toISOString(),
    page: page || req.url,
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '',
    ua: req.headers['user-agent'] || '',
    ref: req.headers['referer'] || '',
    ...extra
  };
  try {
    appendFileSync(HITS_LOG, JSON.stringify(entry) + '\n');
  } catch (e) { /* ignore write errors */ }
}

function isBot(ua) {
  if (!ua) return false;
  const bots = /bot|crawl|spider|slurp|GPTBot|Claude|Anthropic|Google|Bing|Perplexity|ChatGPT|cohere|ai2|applebot/i;
  return bots.test(ua);
}

// --- Request handler ---

const server = createServer((req, res) => {
  const ua = req.headers['user-agent'] || '';
  const bot = isBot(ua);

  // Analytics beacon endpoint
  if (req.method === 'POST' && req.url === '/hit') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 2048) req.destroy(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        logHit(req, data.p, { referrer: data.r, width: data.w, beacon: true });
      } catch (e) { /* ignore bad payloads */ }
      res.writeHead(204);
      res.end();
    });
    return;
  }

  // Analytics stats (protected — only from localhost or with key)
  if (req.url === '/stats' || req.url === '/stats/') {
    const isLocal = req.socket.remoteAddress === '127.0.0.1' || req.socket.remoteAddress === '::1';
    const hasKey = req.url.includes('key=' + (process.env.STATS_KEY || 'rootz2026'));
    if (!isLocal && !hasKey) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }
    try {
      const lines = existsSync(HITS_LOG) ? readFileSync(HITS_LOG, 'utf-8').trim().split('\n') : [];
      const hits = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      const last24h = hits.filter(h => new Date(h.ts) > new Date(Date.now() - 86400000));
      const pages = {};
      const bots = {};
      last24h.forEach(h => {
        pages[h.page] = (pages[h.page] || 0) + 1;
        if (isBot(h.ua)) {
          const name = h.ua.match(/GPTBot|Claude|Anthropic|Google|Bing|Perplexity|ChatGPT|cohere|applebot|bot/i)?.[0] || 'other';
          bots[name] = (bots[name] || 0) + 1;
        }
      });
      const stats = {
        total: hits.length,
        last24h: last24h.length,
        pages,
        bots,
        lastHit: hits.length > 0 ? hits[hits.length - 1] : null
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(stats, null, 2));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ total: 0, error: e.message }));
    }
    return;
  }

  // Log every page view
  logHit(req, req.url, { bot });

  // --- Static routes ---

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

  // Router tour page
  if (req.url === '/router' || req.url === '/router/' || req.url === '/router-tour' || req.url === '/router-tour/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
    res.end(routerTourHtml);
    return;
  }

  // Compliance demo page
  if (req.url === '/compliance' || req.url === '/compliance/') {
    if (complianceHtml) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
      res.end(complianceHtml);
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(indexHtml); // fallback to index until compliance.html is built
    }
    return;
  }

  // Health check
  if (req.url === '/health') {
    const hitCount = existsSync(HITS_LOG) ? readFileSync(HITS_LOG, 'utf-8').trim().split('\n').length : 0;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      service: 'proof.rootz.global',
      version: '2.0.0',
      updated: '2026-05-26',
      pages: ['/', '/tour', '/tech', '/router', '/compliance'],
      hits: hitCount,
      features: ['five-eyes-alignment', 'patent-us-2025-0112783', 'post-quantum', 'compliance-demo', 'analytics']
    }));
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
  console.log(`proof.rootz.global v2.0.0 running on port ${PORT}`);
  console.log(`  Pages: / /tour /tech /router /compliance`);
  console.log(`  Analytics: /hit (beacon) /stats (dashboard)`);
  console.log(`  Discovery: /.well-known/ai`);
});
