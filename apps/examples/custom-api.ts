// Example: calling an arbitrary, untrusted custom API with veil's fetch wrapper.
//
// Run: npm run custom-api   (from apps/examples)
//
// This shows the universal case: veil knows nothing about this endpoint's
// schema. It redacts every string in the JSON body and restores the response.

// 0) Set up an in-process fake upstream FIRST, so veil wraps it. In a real
//    app this step is your network — you just call installRedactFetch once.
globalThis.fetch = (async (input: any, init?: any) => {
  const url = typeof input === 'string' ? input : input.toString();
  console.log('[upstream received URL]', url);
  console.log('[upstream received body]', init?.body ?? '(no body)');
  const body = (init?.body as string) ?? '{}';
  return new Response(JSON.stringify({ ok: true, echoed: JSON.parse(body) }), {
    headers: { 'content-type': 'application/json' },
  });
}) as typeof fetch;

import { installRedactFetch } from '@veil/fetch';

// 1) Install the wrapper. In a real app you'd do this once at startup.
const uninstall = installRedactFetch({
  urls: 'https://api.some-untrusted-provider.com/**',
  categories: 'default',
  request: { body: true, urlQuery: true, headers: false },
  response: { types: ['text/', 'application/json', 'text/event-stream'] },
});

// 2) Make the call. Your code uses the real values; the provider sees tokens.
async function main() {
  try {
    const res = await fetch(
      'https://api.some-untrusted-provider.com/v1/ingest?source=billing',
      {
        method: 'POST',
        body: JSON.stringify({
          customer: {
            email: 'alice@example.com',
            cpf: '529.982.247-25',
            card: '4242 4242 4242 4242',
          },
          note: 'reached out via alice@example.com again',
          token: 'Bearer secret_abcdef1234567890',
        }),
      },
    );
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
