import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Redactor } from '../src/index.js';

// Regression tests for redaction bypasses. Each test represents a shape that
// must NOT leak to the provider. If a future change lets any of these through,
// the test fails — add the fix and keep the test.

test('bypass: email embedded in JSON string value is redacted', () => {
  const r = new Redactor();
  const s = JSON.stringify({ note: 'contact alice@example.com now' });
  const out = r.redact(s);
  assert.ok(!out.includes('alice@example.com'));
  assert.equal(r.buildRestorer().restoreAll(out), s);
});

test('bypass: apikey that looks like a uuid-ish run with sk- prefix', () => {
  const r = new Redactor();
  const out = r.redact('sk-test_abcdef0123456789abcdef0123456789');
  assert.ok(!out.includes('sk-test_abcdef'));
  assert.match(out, /<<PII_APIKEY_1>>/);
});

test('bypass: aws secret with mixed case does not leak', () => {
  const r = new Redactor();
  const aws = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  const out = r.redact(`creds ${aws} end`);
  assert.ok(!out.includes(aws));
});

test('bypass: bearer token in a header-like string is redacted (value only)', () => {
  const r = new Redactor();
  const out = r.redact('Authorization: Bearer supersecretvalue1234');
  assert.ok(!out.includes('supersecretvalue1234'));
  assert.ok(out.includes('Authorization: Bearer'));
  assert.match(out, /<<PII_TOKEN_1>>/);
});

test('bypass: CPF with no separators is redacted when valid', () => {
  const r = new Redactor();
  const out = r.redact('cpf 52998224725 aqui');
  assert.ok(!out.includes('52998224725'));
});

test('bypass: invalid CPF (wrong check digit) is NOT masked — prose preserved', () => {
  // A wrong CPF must not be redacted (validator rejects it). This protects
  // prose containing 11-digit runs from false positives.
  const r = new Redactor();
  const out = r.redact('id 52998224726 here');
  assert.equal(out, 'id 52998224726 here');
});

test('bypass: PEM block does not leak its body and is restored exactly', () => {
  const r = new Redactor();
  const pem = [
    '-----BEGIN EC PRIVATE KEY-----',
    'MHcCAQEEIBGxY2...',
    '-----END EC PRIVATE KEY-----',
  ].join('\n');
  const original = `key=${pem};done`;
  const out = r.redact(original);
  assert.ok(!out.includes('MHcCAQEEIBGxY2'));
  assert.ok(!out.includes('-----BEGIN EC'));
  assert.equal(r.buildRestorer().restoreAll(out), original);
});

test('bypass: dburl with embedded password is fully redacted', () => {
  const r = new Redactor();
  const url = 'postgres://svc:supersecret@db.internal:5432/prod';
  const out = r.redact(`dsn ${url} ok`);
  assert.ok(!out.includes('supersecret'));
  assert.ok(!out.includes(url));
  assert.equal(r.buildRestorer().restoreAll(out), `dsn ${url} ok`);
});

test('bypass: streaming restore never duplicates a token restored at a boundary', () => {
  const r = new Redactor();
  const redacted = r.redact('a alice@example.com b');
  const rest = r.buildRestorer();
  // feed in 1-char slices, then a final big chunk; ensure no dup
  let acc = '';
  for (let i = 0; i < 5; i++) acc += rest.push(redacted[i]!);
  acc += rest.push(redacted.slice(5));
  acc += rest.flush();
  assert.equal(acc, 'a alice@example.com b');
});
