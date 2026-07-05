# veil

Reversible redaction for calling **any HTTP API** on an untrusted provider without leaking PII or secrets.

`veil` wraps `globalThis.fetch`. Before any network call, sensitive values (emails, phones, CPF/CNPJ, API keys, cards, JWTs, private keys, AWS secrets, bearer tokens, …) are replaced with opaque, stable tokens like `<<PII_EMAIL_1>>`. The upstream provider only ever sees tokens. When the response comes back, `veil` restores the original values exactly — including mid-stream, byte-for-byte. Your code reads the real data; the provider never does.

It is **universal**: the fetch wrapper does not assume anything about the endpoint, the schema, or whether it's an LLM. Any fetch to any URL is covered. Schema-aware SDK sugar (`veil/openai`, `veil/anthropic`) is optional and ships on top.

- Zero runtime dependencies in the core engine.
- Isomorphic: Node 20+, browsers, Edge, Bun, Deno. Only standard Web APIs.
- No telemetry, no own network, no persisted state. The token↔original map lives in memory for the duration of a single fetch call and is dropped after.

## Threat model

- **Untrusted:** the upstream provider (arbitrary endpoint). It may log, train on, or resell your payload.
- **Trusted:** your process that imports `veil`.
- **Redaction happens before the network.** The provider sees only opaque tokens.
- **Restoration happens in your process, after the response.**
- The token↔original mapping is held **in memory only**, for the duration of the call. It is never persisted, logged, or sent anywhere.
- No telemetry, no phone-home, no external services.

## Install

```sh
npm install veil
```

`veil` ships two packages: `@veil/core` (the pure engine) and `@veil/fetch` (the universal fetch wrapper). For most users the `veil` umbrella import is enough:

```ts
import { installRedactFetch } from 'veil/fetch';
```

## Usage — the fetch wrapper (primary)

Install the wrapper once at the start of your program. Every `fetch()` afterwards is redacted/restored automatically:

```ts
import { installRedactFetch } from 'veil/fetch';

const uninstall = installRedactFetch({
  // Which calls to redact. Default: all. Accepts a glob, an array of globs,
  // or a predicate function. Omit to redact every fetch.
  urls: ['https://upstream.example.com/**'],

  // Which categories to redact. Default: DEFAULT_CATEGORIES.
  // 'all' also enables the high-false-positive opt-in categories.
  categories: 'all',

  // What to touch on the request side.
  request: {
    body: true,       // redact JSON/string/FormData/URLSearchParams/streaming bodies
    urlQuery: true,   // redact query-string values (path is never touched)
    headers: false,   // OFF by default; see "Headers" below
  },

  // Which response content-types to restore.
  response: {
    types: ['text/', 'application/json', 'text/event-stream'],
  },
});

// Any fetch is now safe:
const r = await fetch('https://upstream.example.com/api/whatever', {
  method: 'POST',
  body: JSON.stringify({ user: { email: 'alice@example.com' } }),
});

// Upstream received: {"user":{"email":"<<PII_EMAIL_1>>"}}
// Your code sees the restored value:
const data = await r.json();
console.log(data.user.email); // 'alice@example.com'

// When you want to remove the wrapper:
uninstall();
```

### What gets redacted on the request

- **JSON bodies** are parsed and walked recursively. Every string value is redacted, regardless of where it sits in the schema. Unknown fields pass through untouched.
- **Plain string bodies** are redacted as text.
- **`URLSearchParams`** and **`FormData`** have their string values redacted; `Blob`/`File` entries pass through.
- **`ReadableStream` upload bodies** are piped through a redacting `TransformStream`. Streaming uploads work.
- **Binary bodies** (`ArrayBuffer`, typed arrays, non-text `Blob`) are **never touched**.
- **URL query string** values are redacted. The path is never modified.

### Headers (off by default)

Headers are **not redacted by default**. `Authorization` and custom auth headers are too easy to break. If you opt in, `veil` only redacts the values of headers you list explicitly — it never default-scans all headers:

```ts
installRedactFetch({
  urls: 'https://up.example.com/**',
  request: {
    headers: ['x-customer-email'],          // array form
    // or: headers: { allow: ['x-customer-email'] },
  },
});
```

### What gets restored on the response

A single `Restorer` is created per fetch call (in a closure, sharing the request's token map). Restoration depends on the response `content-type`:

- **`text/event-stream` (SSE):** the body is piped through a restoring `TransformStream`. Tokens split across chunk boundaries are reassembled via a safe lookahead; `flush()` finalizes at the end.
- **`application/json` and `text/*`:** the body is buffered, restored, and the `Response` is rebuilt with the same status, status text, and headers.
- **Non-text content-types** (images, audio, `application/octet-stream`, …): **passed through untouched.**

The wrapper preserves `Response` semantics — status, headers, trailers — and only swaps the body. `gzip`/`brotli` are decoded by the native fetch before `veil` sees the text.

### Concurrency & isolation

Each fetch call gets its own `Redactor` + `Restorer` pair. There is no global state and no cross-talk between concurrent calls. Two parallel requests with different emails each restore their own email.

### Idempotent installation

`installRedactFetch()` returns an uninstall function that restores the original `fetch`. Installing twice does not double-wrap; uninstalling restores the original.

## Categories

Default categories are tuned for **high sensitivity, low false-positive rate**. Opt-in categories are useful but tend to match prose; enable them only when needed.

| Category     | Token             | Default | Opt-in | Notes |
|--------------|-------------------|:------:|:------:|-------|
| `email`      | `<<PII_EMAIL_n>>`    | ✓ |   | RFC-ish local-part@domain |
| `phone`      | `<<PII_PHONE_n>>`    | ✓ |   | E.164 (`+…`) or `(NN)` area code; avoids swallowing CPF/card |
| `cpf`        | `<<PII_CPF_n>>`      | ✓ |   | Brazilian CPF, check-digit validated |
| `cnpj`       | `<<PII_CNPJ_n>>`     | ✓ |   | Brazilian CNPJ, check-digit validated |
| `apikey`     | `<<PII_APIKEY_n>>`   | ✓ |   | `sk-…`, `sk_live_…`, `AKIA…`, `ghp_…`, `xox…`, `AIza…`, `api_key…` |
| `card`       | `<<PII_CARD_n>>`     | ✓ |   | Credit card numbers, Luhn-validated |
| `dburl`      | `<<PII_DBURL_n>>`    | ✓ |   | `postgres://`, `mysql://`, `mongodb://`, `redis://`, … |
| `jwt`        | `<<PII_JWT_n>>`      | ✓ |   | Three base64url segments, header validated |
| `privatekey` | `<<PII_PRIVATEKEY_n>>` | ✓ |   | PEM `-----BEGIN … PRIVATE KEY-----` blocks |
| `aws`        | `<<PII_AWS_n>>`      | ✓ |   | 40-char AWS secret access keys |
| `token`      | `<<PII_TOKEN_n>>`    | ✓ |   | Value after `Bearer`, `token=`, `api_key=`, `Authorization:` |
| `ip`         | `<<PII_IP_n>>`       |   | ✓ | IPv4 addresses |
| `mac`        | `<<PII_MAC_n>>`      |   | ✓ | MAC addresses |
| `cep`        | `<<PII_CEP_n>>`      |   | ✓ | Brazilian postal codes |
| `pis`        | `<<PII_PIS_n>>`      |   | ✓ | Brazilian PIS/NIS, check-digit validated |
| `ssn`        | `<<PII_SSN_n>>`      |   | ✓ | US SSN, SSA structural rules |

Non-overlap resolution: longer/more-specific patterns win. PEM private keys, database URLs, JWTs, and AWS secrets are matched before the generic `apikey` pattern so the canonical span is preserved. The same value always maps to the same token within one call.

## Using the core engine directly

If you don't want the fetch wrapper (e.g. you redact a log line, a prompt, a file), use `@veil/core`:

```ts
import { Redactor } from 'veil/core';

const r = new Redactor();                 // default categories
const redacted = r.redact('email alice@example.com, cpf 529.982.247-25');

const rest = r.buildRestorer();
const back = rest.restoreAll(redacted);   // exact original

// Streaming restore:
const s = r.buildRestorer();
let out = '';
for (const chunk of chunks) out += s.push(chunk);
out += s.flush();
```

## Configuration reference

```ts
interface RedactFetchOptions {
  urls?: string | string[] | ((url: string) => boolean);
  categories?: readonly RedactCategory[] | 'all' | 'default';
  request?: {
    body?: boolean;        // default true
    urlQuery?: boolean;    // default true
    headers?: boolean | string[] | { allow?: string[] };  // default false
  };
  response?: {
    types?: string[];      // default ['text/', 'application/json', 'text/event-stream']
  };
}
```

## When NOT to use veil

- **You already fully control the provider and the transport** (e.g. your own service over mTLS). Redaction adds overhead for no benefit.
- **Your payload is meant to be opaque binary** and you never send text PII. `veil` won't touch binary bodies anyway, but there's nothing to redact.
- **You need the provider to see the real PII to do its job** (e.g. an email-sending API that needs the recipient address). Redacting defeats the purpose. Consider redacting only the fields the provider doesn't need.
- **You require hard, cryptographic guarantees of non-disclosure.** `veil` is deterministic redaction, not encryption. If the provider must process the value, a token breaks that. If you need zero-knowledge processing, use a different architecture.
- **Opt-in categories (IP, MAC, CEP, PIS, SSN) on prose-heavy inputs.** These match common shapes and will flag ordinary text. Prefer false-negatives over masking prose; leave them off unless your payload is structured.

## Comparison

| | veil | server-side proxy | DLP gateways | field-masking SDKs |
|---|---|---|---|---|
| Works with any HTTP API | ✓ | ✓ | ✓ | per-SDK |
| Redaction before network | ✓ | ✓ | ✓ | ✓ |
| Exact restoration in-process | ✓ | ✓ (proxy) | varies | ✓ |
| Streaming-safe (SSE) restore | ✓ | varies | varies | varies |
| No infra to run | ✓ | ✗ (run a proxy) | ✗ | ✓ |
| No provider trust needed | ✓ | ✓ | ✓ | ✓ |
| Zero deps / isomorphic core | ✓ | n/a | n/a | varies |

`veil` is library-first: no proxy to deploy, no gateway to route through. The `veil-proxy` CLI companion exists for non-JS environments (curl, Python, Go, IDEs) and reuses the same core.

## Security & disclosure

See [SECURITY.md](./SECURITY.md) for the vulnerability disclosure policy, including how to report redaction bypasses.

## License

MIT.
