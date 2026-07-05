import { test } from 'node:test';
import assert from 'node:assert/strict';
import { installRedactFetch } from '../src/index.js';

// ---------------------------------------------------------------------------
// Test helpers: a configurable mock fetch.
// ---------------------------------------------------------------------------

interface MockSpec {
  /** Fixed chunks to emit as the response body (for SSE/stream tests). */
  chunks?: Uint8Array[];
  /** Or a single body string. */
  body?: string;
  status?: number;
  headers?: Record<string, string>;
  /** Capture the request as seen by the upstream. */
  onRequest?: (url: string, init: RequestInit | undefined) => void;
}

function makeMockFetch(spec: MockSpec): typeof fetch {
  return (async (input: any, init?: any) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (spec.onRequest) spec.onRequest(url, init);

    let bodyStream: ReadableStream<Uint8Array>;
    if (spec.chunks) {
      bodyStream = new ReadableStream({
        start(controller) {
          for (const c of spec.chunks!) controller.enqueue(c);
          controller.close();
        },
      });
    } else {
      const text = spec.body ?? '';
      bodyStream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(text));
          controller.close();
        },
      });
    }

    return new Response(bodyStream, {
      status: spec.status ?? 200,
      headers: spec.headers ?? { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
}

function withMock(spec: MockSpec, fn: (mock: typeof fetch) => Promise<void>): Promise<void> {
  const mock = makeMockFetch(spec);
  const prev = globalThis.fetch;
  globalThis.fetch = mock;
  return fn(mock).finally(() => {
    globalThis.fetch = prev;
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('fetch: JSON request with nested PII → upstream sees only tokens; response restored', async () => {
  const captured: { url: string; body: string } = { url: '', body: '' };
  await withMock(
    {
      body: '{"ok":true,"echo":"<<PII_EMAIL_1>>"}',
      headers: { 'content-type': 'application/json' },
      onRequest: (url, init) => {
        captured.url = url;
        captured.body = (init?.body as string) ?? '';
      },
    },
    async () => {
      const uninstall = installRedactFetch({
        urls: 'https://up.example.com/**',
      });
      try {
        const r = await fetch('https://up.example.com/api', {
          method: 'POST',
          body: JSON.stringify({ user: { email: 'alice@example.com' }, note: 'hi' }),
        });
        const json = await r.json();
        // upstream received only tokens
        assert.deepEqual(JSON.parse(captured.body), {
          user: { email: '<<PII_EMAIL_1>>' },
          note: 'hi',
        });
        // response restored
        assert.deepEqual(json, { ok: true, echo: 'alice@example.com' });
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: SSE streaming response with token split across chunks → restored with flush', async () => {
  // The upstream echoes the request token in SSE chunks. We split the token
  // across two chunks.
  const token = '<<PII_EMAIL_1>>';
  const data = `data: {"e":"${token}"}\n\n`;
  // split so the token straddles the boundary
  const cut = data.indexOf('EMAIL') ;
  const a = data.slice(0, cut);
  const b = data.slice(cut);
  await withMock(
    {
      chunks: [new TextEncoder().encode(a), new TextEncoder().encode(b)],
      headers: { 'content-type': 'text/event-stream' },
      onRequest: (_url, init) => {
        // ensure request redacted the email
        assert.match((init?.body as string) ?? '', /<<PII_EMAIL_1>>/);
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        const r = await fetch('https://up.example.com/stream', {
          method: 'POST',
          body: JSON.stringify({ email: 'alice@example.com' }),
        });
        const reader = r.body!.getReader();
        let acc = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          acc += new TextDecoder().decode(value);
        }
        assert.equal(acc, `data: {"e":"alice@example.com"}\n\n`);
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: URL query redacted; path intact', async () => {
  let seenUrl = '';
  await withMock(
    {
      body: '{}',
      onRequest: (url) => {
        seenUrl = url;
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        await fetch('https://up.example.com/api/x?email=alice@example.com&keep=1');
        // < and > are URL-encoded in the query string value.
        assert.match(seenUrl, /\/api\/x\?email=%3C%3CPII_EMAIL_1%3E%3E&keep=1/);
        assert.ok(seenUrl.includes('/api/x'));
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: binary (image) response passes through untouched', async () => {
  // 8 bytes of non-text content
  const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  let requestBodySeen: any;
  await withMock(
    {
      chunks: [bytes],
      headers: { 'content-type': 'image/png' },
      onRequest: (_u, init) => {
        requestBodySeen = init?.body;
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        const buf = bytes.slice();
        const r = await fetch('https://up.example.com/img', {
          method: 'POST',
          body: buf,
        });
        const ab = await r.arrayBuffer();
        assert.deepEqual(new Uint8Array(ab), bytes);
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: GET with no body → only query redacted', async () => {
  let seenUrl = '';
  let seenInit: any;
  await withMock(
    {
      body: 'ok',
      headers: { 'content-type': 'text/plain' },
      onRequest: (url, init) => {
        seenUrl = url;
        seenInit = init;
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        const r = await fetch('https://up.example.com/get?q=alice@example.com');
        assert.match(seenUrl, /q=%3C%3CPII_EMAIL_1%3E%3E/);
        // no body sent
        assert.equal(seenInit?.body, undefined);
        const text = await r.text();
        assert.equal(text, 'ok');
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: headers OFF by default → Authorization intact', async () => {
  let authHeader: string | null = null;
  await withMock(
    {
      body: '{}',
      onRequest: (_u, init) => {
        const h = new Headers(init?.headers);
        authHeader = h.get('authorization');
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        await fetch('https://up.example.com/api', {
          method: 'POST',
          headers: { authorization: 'Bearer secret1234567890' },
          body: JSON.stringify({ x: 'alice@example.com' }),
        });
        assert.equal(authHeader, 'Bearer secret1234567890');
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: headers ON with allow list → listed header redacted', async () => {
  let authHeader: string | null = null;
  await withMock(
    {
      body: '{}',
      onRequest: (_u, init) => {
        const h = new Headers(init?.headers);
        authHeader = h.get('x-custom');
      },
    },
    async () => {
      const uninstall = installRedactFetch({
        urls: 'https://up.example.com/**',
        request: { headers: ['x-custom'] },
      });
      try {
        await fetch('https://up.example.com/api', {
          method: 'POST',
          headers: { 'x-custom': 'alice@example.com', authorization: 'Bearer secret1234567890' },
          body: '{}',
        });
        assert.equal(authHeader, '<<PII_EMAIL_1>>');
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: uninstall restores original fetch', async () => {
  const prev = globalThis.fetch;
  const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
  assert.notEqual(globalThis.fetch, prev);
  uninstall();
  assert.equal(globalThis.fetch, prev);
});

test('fetch: concurrent calls have independent restorers (no cross-talk)', async () => {
  // Two calls with different emails; each response echoes its own token.
  let n = 0;
  const emails = ['alice@example.com', 'bob@example.com'];
  await withMock(
    {
      onRequest: (_u, init) => {
        // echo the request body back as the response body
        n++;
      },
    },
    async (mock) => {
      // Override the mock to echo the request body.
      let callIdx = 0;
      globalThis.fetch = (async (input: any, init?: any) => {
        const idx = callIdx++;
        const body = (init?.body as string) ?? '';
        const resp = new Response(body, {
          headers: { 'content-type': 'application/json' },
        });
        return resp;
      }) as typeof fetch;

      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        const [r1, r2] = await Promise.all([
          fetch('https://up.example.com/a', { method: 'POST', body: JSON.stringify({ e: emails[0] }) }),
          fetch('https://up.example.com/b', { method: 'POST', body: JSON.stringify({ e: emails[1] }) }),
        ]);
        const j1 = await r1.json();
        const j2 = await r2.json();
        assert.equal(j1.e, 'alice@example.com');
        assert.equal(j2.e, 'bob@example.com');
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: echo API restores token in every field', async () => {
  await withMock({}, async () => {
    globalThis.fetch = (async (input: any, init?: any) => {
      const body = (init?.body as string) ?? '';
      // echo the same body multiple times in a JSON wrapper
      const echo = JSON.stringify({ a: body, b: body, c: body });
      return new Response(echo, { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;

    const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
    try {
      const r = await fetch('https://up.example.com/echo', {
        method: 'POST',
        body: JSON.stringify({ x: 'alice@example.com' }),
      });
      const j = await r.json();
      // Each field should contain the restored JSON
      assert.equal(JSON.parse(j.a).x, 'alice@example.com');
      assert.equal(JSON.parse(j.b).x, 'alice@example.com');
      assert.equal(JSON.parse(j.c).x, 'alice@example.com');
    } finally {
      uninstall();
    }
  });
});

test('fetch: non-matching URL is not redacted (passthrough)', async () => {
  let seenBody = '';
  await withMock(
    {
      body: '{}',
      onRequest: (_u, init) => {
        seenBody = (init?.body as string) ?? '';
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://other.example.com/**' });
      try {
        await fetch('https://up.example.com/api', {
          method: 'POST',
          body: JSON.stringify({ e: 'alice@example.com' }),
        });
        assert.equal(seenBody, JSON.stringify({ e: 'alice@example.com' }));
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: URLSearchParams body redacted', async () => {
  let seenBody = '';
  await withMock(
    {
      body: 'ok',
      onRequest: (_u, init) => {
        seenBody = (init?.body as URLSearchParams).toString();
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        const params = new URLSearchParams();
        params.append('email', 'alice@example.com');
        params.append('keep', '1');
        await fetch('https://up.example.com/form', {
          method: 'POST',
          body: params,
        });
        assert.match(seenBody, /email=%3C%3CPII_EMAIL_1%3E%3E/);
        assert.match(seenBody, /keep=1/);
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: idempotent install does not double-wrap', async () => {
  const prev = globalThis.fetch;
  const u1 = installRedactFetch({ urls: 'https://up.example.com/**' });
  const wrapped = globalThis.fetch;
  const u2 = installRedactFetch({ urls: 'https://up.example.com/**' });
  assert.equal(globalThis.fetch, wrapped); // no double wrap
  u2();
  u1();
  assert.equal(globalThis.fetch, prev);
});
