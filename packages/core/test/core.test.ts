import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Redactor, Restorer } from '../src/index.js';
import {
  cpfValid,
  cnpjValid,
  pisValid,
  ssnValid,
  cepValid,
  ipv4Valid,
  luhnValid,
  awsSecretValid,
  jwtValid,
} from '../src/index.js';

// A valid CPF (random, check-digit correct): 529.982.247-25
const VALID_CPF = '529.982.247-25';
const VALID_CNPJ = '11.222.333/0001-81';
const VALID_PIS = '120.5114.035-0';
const VALID_SSN = '123-45-6789';
const VALID_CEP = '01310-100';

test('validators: CPF valid/invalid', () => {
  assert.equal(cpfValid(VALID_CPF), true);
  assert.equal(cpfValid('111.111.111-11'), false);
  assert.equal(cpfValid('529.982.247-26'), false);
});

test('validators: CNPJ valid/invalid', () => {
  assert.equal(cnpjValid(VALID_CNPJ), true);
  assert.equal(cnpjValid('11.222.333/0001-82'), false);
});

test('validators: PIS valid/invalid', () => {
  assert.equal(pisValid(VALID_PIS), true);
  assert.equal(pisValid('120.5114.035-5'), false);
});

test('validators: SSN structural rules', () => {
  assert.equal(ssnValid(VALID_SSN), true);
  assert.equal(ssnValid('000-12-3456'), false); // area 000
  assert.equal(ssnValid('666-12-3456'), false); // area 666
  assert.equal(ssnValid('900-12-3456'), false); // area 900-999
});

test('validators: CEP', () => {
  assert.equal(cepValid(VALID_CEP), true);
  assert.equal(cepValid('01310'), false);
});

test('validators: IPv4', () => {
  assert.equal(ipv4Valid('192.168.0.1'), true);
  assert.equal(ipv4Valid('256.0.0.1'), false);
  assert.equal(ipv4Valid('01.0.0.1'), false);
});

test('validators: Luhn', () => {
  // 4242 4242 4242 4242 is a valid test card number
  assert.equal(luhnValid('4242 4242 4242 4242'), true);
  assert.equal(luhnValid('4242 4242 4242 4243'), false);
});

test('validators: AWS secret', () => {
  assert.equal(awsSecretValid('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), true);
  // Real AWS keys have mixed case; all-lowercase 40-char runs are rejected.
  assert.equal(awsSecretValid('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), false);
  assert.equal(awsSecretValid('short'), false);
});

test('validators: JWT', () => {
  // header eyJhbGciOiJIUzI1NiJ9 -> {"alg":"HS256"}
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  assert.equal(jwtValid(jwt), true);
  assert.equal(jwtValid('not.a.jwt'), false);
});

test('redact: email produces stable token', () => {
  const r = new Redactor();
  const out = r.redact('Contact alice@example.com or alice@example.com again');
  assert.equal(out, 'Contact <<PII_EMAIL_1>> or <<PII_EMAIL_1>> again');
  const rest = r.buildRestorer();
  assert.equal(rest.restoreAll(out), 'Contact alice@example.com or alice@example.com again');
});

test('redact: same value across categories reuses token within category', () => {
  const r = new Redactor();
  const out = r.redact('a@b.com and a@b.com');
  assert.match(out, /<<PII_EMAIL_1>> and <<PII_EMAIL_1>>/);
});

test('redact: CPF redacted and restored', () => {
  const r = new Redactor();
  const out = r.redact(`CPF ${VALID_CPF} aqui`);
  assert.match(out, /<<PII_CPF_1>>/);
  assert.equal(r.buildRestorer().restoreAll(out), `CPF ${VALID_CPF} aqui`);
});

test('redact: invalid CPF is NOT redacted (validator)', () => {
  const r = new Redactor();
  const out = r.redact('bad 111.111.111-11 no');
  assert.equal(out, 'bad 111.111.111-11 no');
});

test('redact: card via Luhn', () => {
  const r = new Redactor();
  const out = r.redact('card 4242 4242 4242 4242 ok');
  assert.match(out, /<<PII_CARD_1>>/);
  assert.equal(r.buildRestorer().restoreAll(out), 'card 4242 4242 4242 4242 ok');
});

test('redact: non-overlap — private key wins over apikey', () => {
  const r = new Redactor();
  const pem = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIBOgIBAAJBAKjQ4Z',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');
  const out = r.redact(`key: ${pem}`);
  assert.match(out, /<<PII_PRIVATEKEY_1>>/);
  assert.equal(r.buildRestorer().restoreAll(out), `key: ${pem}`);
});

test('redact: dburl redacted', () => {
  const r = new Redactor();
  const out = r.redact('postgres://user:pass@host:5432/db');
  assert.match(out, /<<PII_DBURL_1>>/);
});

test('redact: jwt redacted', () => {
  const r = new Redactor();
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const out = r.redact(`tok ${jwt} end`);
  assert.match(out, /<<PII_JWT_1>>/);
});

test('redact: keyword token redacts only the value', () => {
  const r = new Redactor();
  const out = r.redact('Authorization: Bearer abcdef1234567890');
  assert.equal(out, 'Authorization: Bearer <<PII_TOKEN_1>>');
  assert.equal(r.buildRestorer().restoreAll(out), 'Authorization: Bearer abcdef1234567890');
});

test('redact: token= variant', () => {
  const r = new Redactor();
  const out = r.redact('token=abcdef1234567890');
  assert.equal(out, 'token=<<PII_TOKEN_1>>');
});

test('redact: api_key= variant', () => {
  const r = new Redactor();
  const out = r.redact('api_key=abcdef1234567890123');
  assert.equal(out, 'api_key=<<PII_TOKEN_1>>');
});

test('redact: opt-in IP not redacted by default', () => {
  const r = new Redactor(); // default
  const out = r.redact('server at 192.168.0.1 down');
  assert.equal(out, 'server at 192.168.0.1 down');
});

test('redact: opt-in IP redacted when enabled', () => {
  const r = new Redactor({ categories: ['ip'] });
  const out = r.redact('server at 192.168.0.1 down');
  assert.match(out, /<<PII_IP_1>>/);
});

test('redact: all categories includes opt-in', () => {
  const r = new Redactor({ categories: 'all' });
  const out = r.redact(`ip 192.168.0.1 ssn ${VALID_SSN}`);
  assert.match(out, /<<PII_IP_1>>/);
  assert.match(out, /<<PII_SSN_1>>/);
});

test('restorer: streaming char-by-char round trip', () => {
  const r = new Redactor();
  const original = 'email alice@example.com and cpf 529.982.247-25 end';
  const redacted = r.redact(original);
  const rest = r.buildRestorer();
  let reconstructed = '';
  for (const ch of redacted) {
    reconstructed += rest.push(ch);
  }
  reconstructed += rest.flush();
  assert.equal(reconstructed, original);
});

test('restorer: streaming chunk-by-chunk round trip', () => {
  const r = new Redactor();
  const original = 'x alice@example.com y 529.982.247-25 z';
  const redacted = r.redact(original);
  const rest = r.buildRestorer();
  let reconstructed = '';
  // arbitrary chunk sizes
  const sizes = [3, 7, 1, 12, 5, 2, 9, 4];
  let i = 0;
  for (const s of sizes) {
    reconstructed += rest.push(redacted.slice(i, i + s));
    i += s;
  }
  if (i < redacted.length) reconstructed += rest.push(redacted.slice(i));
  reconstructed += rest.flush();
  assert.equal(reconstructed, original);
});

test('restorer: token split exactly across chunks', () => {
  const r = new Redactor();
  const redacted = r.redact('alice@example.com');
  // redacted = <<PII_EMAIL_1>> ; split at midpoint
  const a = redacted.slice(0, 7); // <<PII_E
  const b = redacted.slice(7);    // MAIL_1>>
  const rest = r.buildRestorer();
  let out = rest.push(a);
  out += rest.push(b);
  out += rest.flush();
  assert.equal(out, 'alice@example.com');
});

test('restorer: unknown <<PII_...>> with closing marker passes through', () => {
  const rest = new Restorer(new Map());
  assert.equal(rest.restoreAll('text <<PII_UNKNOWN_9>> end'), 'text <<PII_UNKNOWN_9>> end');
});

test('restorer: literal << not part of token', () => {
  const rest = new Restorer(new Map());
  assert.equal(rest.restoreAll('a << b'), 'a << b');
});

test('echo API: token appears many times, all restored', () => {
  const r = new Redactor();
  const redacted = r.redact('alice@example.com');
  const echoed = `{"echo":"${redacted}","again":"${redacted}","list":["${redacted}"]}`;
  const rest = r.buildRestorer();
  assert.equal(rest.restoreAll(echoed), '{"echo":"alice@example.com","again":"alice@example.com","list":["alice@example.com"]}');
});

test('redact: apikey sk- prefix', () => {
  const r = new Redactor();
  const out = r.redact('key sk-abcdefghijklmnopqrstuvwxyz123456');
  assert.match(out, /<<PII_APIKEY_1>>/);
});

test('redact: round trip with mixed categories', () => {
  const r = new Redactor();
  const original = `Contact alice@example.com, CPF ${VALID_CPF}, key sk-abcdefghijklmnopqrstuvwxyz123456 and Bearer secret1234567890`;
  const redacted = r.redact(original);
  const rest = r.buildRestorer();
  assert.equal(rest.restoreAll(redacted), original);
  // ensure no PII leaks in redacted form
  assert.equal(redacted.includes('alice@example.com'), false);
  assert.equal(redacted.includes(VALID_CPF), false);
  assert.equal(redacted.includes('secret1234567890'), false);
});
