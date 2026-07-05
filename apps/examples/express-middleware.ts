// Example: an Express server that wraps outbound fetch with veil so any
// backend call it makes to an untrusted provider is redacted.
//
// Run: npm run express-middleware
//
// This demonstrates veil used as outbound protection inside a server. The
// Express route receives a request from your own client, then calls an
// untrusted upstream on the client's behalf — veil ensures the upstream never
// sees the client's PII.

// 0) Fake upstream first, so veil wraps it.
globalThis.fetch = (async (_input: any, init?: any) => {
  console.log('[upstream saw]', init?.body);
  const body = JSON.parse((init?.body as string) ?? '{}');
  return new Response(JSON.stringify({ processed: true, seen: body }), {
    headers: { 'content-type': 'application/json' },
  });
}) as typeof fetch;

import { installRedactFetch } from '@veil/fetch';
import { createServer } from 'node:http';

// Install once at boot. All outbound fetch to the upstream is redacted.
const uninstall = installRedactFetch({
  urls: 'https://api.untrusted-upstream.com/**',
  categories: 'default',
  request: { body: true, urlQuery: true, headers: false },
  response: { types: ['text/', 'application/json', 'text/event-stream'] },
});

const server = createServer(async (req, res) => {
  if (req.method !== 'POST' || req.url !== '/proxy') {
    res.writeHead(404).end('not found');
    return;
  }
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const payload = JSON.parse(Buffer.concat(chunks).toString('utf-8'));

  // Outbound call to the untrusted upstream. veil redacts it.
  const up = await fetch('https://api.untrusted-upstream.com/v1/work', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  const data = await up.json();

  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify(data));
});

server.listen(0, () => {
  const addr = server.address() as { port: number };
  console.log('listening on port', addr.port);
  console.log('try: curl -s localhost:%d/proxy -H "content-type: application/json" -d \'{"email":"alice@example.com"}\'', addr.port);
});

process.on('SIGINT', () => {
  uninstall();
  server.close();
  process.exit(0);
});
