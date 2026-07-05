import { test } from 'node:test';
import assert from 'node:assert/strict';
// Main entry re-exports the fetch wrapper (the primary product).
import { installRedactFetch, VERSION } from '../src/index.js';
// The core engine lives behind the ./core subpath.
import { Redactor } from '../src/core.js';

// The umbrella re-exports the core engine and the fetch wrapper. This smoke
// test verifies the public surface is wired correctly through the re-exports.

test('umbrella: main entry exposes installRedactFetch + VERSION', () => {
  assert.equal(typeof installRedactFetch, 'function');
  assert.equal(typeof VERSION, 'string');
  assert.ok(VERSION.length > 0);
});

test('umbrella: ./core subpath re-exports Redactor', () => {
  const r = new Redactor();
  const out = r.redact('email <<PII_EMAIL_1>>');
  assert.match(out, /<<PII_EMAIL_1>>/);
  assert.equal(r.buildRestorer().restoreAll(out), 'email <<PII_EMAIL_1>>');
});

test('umbrella: fetch wrapper round-trip via re-export', async () => {
  const prev = globalThis.fetch;
  globalThis.fetch = (async (_u: any, init?: any) =>
    new Response(init?.body as string, {
      headers: { 'content-type': 'application/json' },
    })) as typeof fetch;
  try {
    const uninstall = installRedactFetch({ urls: 'https://up.example.com/**' });
    try {
      const res = await fetch('https://up.example.com/api', {
        method: 'POST',
        body: JSON.stringify({ e: '<<PII_EMAIL_1>>' }),
      });
      const j = await res.json();
      assert.equal(j.e, '<<PII_EMAIL_1>>');
    } finally {
      uninstall();
    }
  } finally {
    globalThis.fetch = prev;
  }
});
