import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Redactor } from '../src/index.js';

// A realistic mixed corpus exercising many categories at once. Round-trip
// must be byte-exact and no raw PII may remain in the redacted form.
const CORPUS = [
  // 1. support ticket
  `From: alice@example.com
Reply to: bob.smith+work@corp.co.uk
Phone: +1 (415) 555-1234
CPF: 529.982.247-25
Card on file: 4242 4242 4242 4242
DB: postgres://svc:supersecret@db.internal:5432/prod
Token: Bearer abcdef1234567890xyz
Key: sk-abcdefghijklmnopqrstuvwxyz123456
`,
  // 2. config dump
  `endpoint=https://api.upstream.com/v1/chat
authorization=Bearer ZXlGemVYTjBhVzl1
jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
aws=AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`,
  // 3. prose with no PII (must be unchanged)
  `The quick brown fox jumps over the lazy dog. No sensitive data here, just
plain English prose with numbers like 42 and dates like 2024-01-15.`,
  // 4. PEM block
  `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKjQ4Zfs
-----END RSA PRIVATE KEY-----
signed by alice@example.com`,
];

test('corpus snapshot: round-trip byte-exact and no PII leaks', () => {
  for (let i = 0; i < CORPUS.length; i++) {
    const original = CORPUS[i]!;
    const r = new Redactor();
    const redacted = r.redact(original);
    // No raw PII in redacted form.
    assert.ok(!redacted.includes('alice@example.com'), `corpus ${i}: email leaked`);
    assert.ok(!redacted.includes('529.982.247-25'), `corpus ${i}: CPF leaked`);
    assert.ok(!redacted.includes('4242 4242 4242 4242'), `corpus ${i}: card leaked`);
    assert.ok(!redacted.includes('supersecret'), `corpus ${i}: db pass leaked`);
    assert.ok(!redacted.includes('abcdef1234567890xyz'), `corpus ${i}: bearer leaked`);
    assert.ok(!redacted.includes('sk-abcdefghijklmnopqrstuvwxyz123456'), `corpus ${i}: apikey leaked`);
    assert.ok(!redacted.includes('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), `corpus ${i}: aws leaked`);
    // Round-trip exact.
    const rest = r.buildRestorer();
    assert.equal(rest.restoreAll(redacted), original, `corpus ${i}: round-trip mismatch`);
  }
});

test('corpus: prose-only input is unchanged by redaction', () => {
  const prose = CORPUS[2]!;
  const r = new Redactor();
  assert.equal(r.redact(prose), prose);
});

test('corpus: tokens are stable across repeated values', () => {
  const r = new Redactor();
  const out = r.redact('a@b.com a@b.com a@b.com');
  assert.equal(out, '<<PII_EMAIL_1>> <<PII_EMAIL_1>> <<PII_EMAIL_1>>');
});
