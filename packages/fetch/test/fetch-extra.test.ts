import { test } from 'node:test';
import assert from 'node:assert/strict';
import { installRedactFetch } from '../src/index.js';

function withMock(spec: any, fn: (mock: typeof fetch) => Promise<void>): Promise<void> {
  const mock = (async (input: any, init?: any) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (spec.onRequest) spec.onRequest(url, init);
    let bodyStream: ReadableStream<Uint8Array>;
    if (spec.chunks) {
      bodyStream = new ReadableStream({
        start(controller) {
          for (const c of spec.chunks) controller.enqueue(c);
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
  const prev = globalThis.fetch;
  globalThis.fetch = mock;
  return fn(mock).finally(() => {
    globalThis.fetch = prev;
  });
}

test('fetch: FormData body redacts string values, passes Blob through', async () => {
  let captured: FormData | undefined;
  await withMock(
    {
      body: 'ok',
      onRequest: (_u, init) => {
        captured = init?.body as FormData;
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        const fd = new FormData();
        fd.append('email', 'alice@example.com');
        fd.append('file', new Blob([new Uint8Array([1, 2, 3])], { type: 'image/png' }), 'x.png');
        await fetch('https://up.example.com/upload', { method: 'POST', body: fd });
        assert.equal(captured!.get('email'), '<<PII_EMAIL_1>>');
        assert.ok(captured!.get('file') instanceof Blob);
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: text request body (non-JSON) redacted as text', async () => {
  let seen = '';
  await withMock(
    {
      body: 'reply',
      headers: { 'content-type': 'text/plain' },
      onRequest: (_u, init) => {
        seen = init?.body as string;
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        await fetch('https://up.example.com/txt', {
          method: 'POST',
          headers: { 'content-type': 'text/plain' },
          body: 'contact alice@example.com please',
        });
        assert.match(seen, /<<PII_EMAIL_1>>/);
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: text/plain response restored', async () => {
  await withMock(
    {
      body: 'email is <<PII_EMAIL_1>> ok',
      headers: { 'content-type': 'text/plain' },
      onRequest: (_u, init) => {
        assert.match(init?.body as string, /<<PII_EMAIL_1>>/);
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        const r = await fetch('https://up.example.com/t', {
          method: 'POST',
          body: 'alice@example.com',
        });
        assert.equal(await r.text(), 'email is alice@example.com ok');
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: headers ON object form { allow: [...] }', async () => {
  let seen: string | null = null;
  await withMock(
    {
      body: '{}',
      onRequest: (_u, init) => {
        seen = new Headers(init?.headers).get('x-token');
      },
    },
    async () => {
      const uninstall = installRedactFetch({
        urls: 'https://up.example.com/**',
        request: { headers: { allow: ['x-token'] } },
      });
      try {
        await fetch('https://up.example.com/api', {
          method: 'POST',
          headers: { 'x-token': 'alice@example.com' },
          body: '{}',
        });
        assert.equal(seen, '<<PII_EMAIL_1>>');
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: streaming request body (ReadableStream) redacted', async () => {
  let bodyStream: ReadableStream<Uint8Array> | undefined;
  await withMock(
    {
      body: '{}',
      onRequest: (_u, init) => {
        bodyStream = init?.body as ReadableStream<Uint8Array>;
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        const src = new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('email=alice@example.com'));
            controller.close();
          },
        });
        await fetch('https://up.example.com/stream-up', { method: 'POST', body: src });
        // Drain the (redacted) stream the upstream received.
        const reader = bodyStream!.getReader();
        const dec = new TextDecoder();
        let seen = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          seen += dec.decode(value);
        }
        assert.match(seen, /<<PII_EMAIL_1>>/);
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: URL filter as predicate function', async () => {
  let seen = '';
  await withMock(
    {
      body: '{}',
      onRequest: (_u, init) => {
        seen = init?.body as string;
      },
    },
    async () => {
      const uninstall = installRedactFetch({
        urls: (url) => url.includes('/redact/'),
      });
      try {
        await fetch('https://up.example.com/redact/x', {
          method: 'POST',
          body: JSON.stringify({ e: 'alice@example.com' }),
        });
        assert.match(seen, /<<PII_EMAIL_1>>/);

        seen = '';
        await fetch('https://up.example.com/skip/x', {
          method: 'POST',
          body: JSON.stringify({ e: 'alice@example.com' }),
        });
        assert.equal(seen, JSON.stringify({ e: 'alice@example.com' }));
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: custom response types restricts restoration', async () => {
  await withMock(
    {
      body: '<<PII_EMAIL_1>>',
      headers: { 'content-type': 'application/xml' },
      onRequest: (_u, init) => {
        assert.match(init?.body as string, /<<PII_EMAIL_1>>/);
      },
    },
    async () => {
      const uninstall = installRedactFetch({
        urls: 'https://up.example.com/**',
        response: { types: ['text/'] }, // only text/* restored, not xml
      });
      try {
        const r = await fetch('https://up.example.com/x', {
          method: 'POST',
          body: 'alice@example.com',
        });
        // xml not in restore list → passthrough, token stays
        assert.equal(await r.text(), '<<PII_EMAIL_1>>');
      } finally {
        uninstall();
      }
    },
  );
});

test('fetch: re-install after uninstall works', async () => {
  let seen = '';
  await withMock(
    {
      body: '{}',
      onRequest: (_u, init) => {
        seen = init?.body as string;
      },
    },
    async () => {
      const u = installRedactFetch({ urls: 'https://up.example.com/**' });
      u();
      // reinstall
      const u2 = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        await fetch('https://up.example.com/api', {
          method: 'POST',
          body: JSON.stringify({ e: 'alice@example.com' }),
        });
        assert.match(seen, /<<PII_EMAIL_1>>/);
      } finally {
        u2();
      }
    },
  );
});

test('fetch: status and headers preserved on restored response', async () => {
  await withMock(
    {
      body: '{"e":"<<PII_EMAIL_1>>"}',
      status: 202,
      headers: { 'content-type': 'application/json', 'x-trace': 'abc' },
      onRequest: (_u, init) => {
        assert.match(init?.body as string, /<<PII_EMAIL_1>>/);
      },
    },
    async () => {
      const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
      try {
        const r = await fetch('https://up.example.com/api', {
          method: 'POST',
          body: JSON.stringify({ e: 'alice@example.com' }),
        });
        assert.equal(r.status, 202);
        assert.equal(r.headers.get('x-trace'), 'abc');
        assert.equal((await r.json()).e, 'alice@example.com');
      } finally {
        uninstall();
      }
    },
  );
});
