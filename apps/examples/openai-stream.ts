// Example: streaming a chat completion from an OpenAI-compatible endpoint
// with PII redacted on the way out and restored on the way back.
//
// Run: npm run openai-stream

// 0) Fake upstream first, so Airlock wraps it.
globalThis.fetch = (async (_input: any, init?: any) => {
  const body = JSON.parse((init?.body as string) ?? '{}');
  const userMsg = body?.messages?.[1]?.content ?? '';
  console.log('[upstream saw]', init?.body);
  const chunks = [
    `data: {"choices":[{"delta":{"content":"hi "}}]}\n\n`,
    `data: {"choices":[{"delta":{"content":"${userMsg}"}}]}\n\n`,
    `data: [DONE]\n\n`,
  ];
  const stream = new ReadableStream({
    start(controller) {
      for (const c of chunks) controller.enqueue(new TextEncoder().encode(c));
      controller.close();
    },
  });
  return new Response(stream, {
    headers: { 'content-type': 'text/event-stream' },
  });
}) as typeof fetch;

import { installRedactFetch } from '@airlock/fetch';

const BASE = process.env.OPENAI_BASE_URL || 'https://api.openai.com';
const KEY = process.env.OPENAI_API_KEY || 'sk-fake-key';

const uninstall = installRedactFetch({
  urls: `${BASE}/**`,
  categories: 'default',
  request: { body: true, urlQuery: true, headers: false },
  response: { types: ['text/', 'application/json', 'text/event-stream'] },
});

async function main() {
  try {
    const res = await fetch(`${BASE}/v1/chat/completions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [
          { role: 'system', content: 'You are a helpful assistant.' },
          { role: 'user', content: 'My email is alice@example.com, please confirm.' },
        ],
        stream: true,
      }),
    });

    const reader = res.body!.getReader();
    const dec = new TextDecoder();
    let full = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      full += dec.decode(value, { stream: true });
    }
    full += dec.decode();
    console.log('[your code sees the restored stream]');
    console.log(full);
  } finally {
    uninstall();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
