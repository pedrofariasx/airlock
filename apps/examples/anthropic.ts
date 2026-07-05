// Example: calling an Anthropic-style messages endpoint with Airlock's fetch
// wrapper. Same universal approach — Airlock doesn't need to know Anthropic's
// schema; it redacts every string in the body and restores the response.
//
// Run: npm run anthropic

// 0) Fake upstream first.
globalThis.fetch = (async (_input: any, init?: any) => {
  console.log('[upstream saw]', init?.body);
  const body = JSON.parse((init?.body as string) ?? '{}');
  const userText = body?.messages?.[0]?.content ?? '';
  return new Response(
    JSON.stringify({ id: 'msg_1', content: [{ type: 'text', text: `got it: ${userText}` }] }),
    { headers: { 'content-type': 'application/json' } },
  );
}) as typeof fetch;

import { installRedactFetch } from '@airlock/fetch';

const BASE = process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com';
const KEY = process.env.ANTHROPIC_API_KEY || 'sk-ant-fake-key';

const uninstall = installRedactFetch({
  urls: `${BASE}/**`,
  categories: 'default',
  request: { body: true, urlQuery: true, headers: false },
  response: { types: ['text/', 'application/json', 'text/event-stream'] },
});

async function main() {
  try {
    const res = await fetch(`${BASE}/v1/messages`, {
      method: 'POST',
      headers: { 'x-api-key': KEY, 'content-type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-3-5-sonnet-20241022',
        max_tokens: 256,
        messages: [
          { role: 'user', content: 'Please reach me at alice@example.com.' },
        ],
      }),
    });
    const data = await res.json();
    console.log('[your code sees]', JSON.stringify(data, null, 2));
  } finally {
    uninstall();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
