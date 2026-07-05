# Security Policy

## Supported versions

The latest minor release of `veil` is supported. Fixes are released as patches.

## Reporting a vulnerability

The core guarantee of `veil` is: **sensitive values must not reach the untrusted provider in cleartext.** The most important class of bug here is a **redaction bypass** — a value that should be tokenized but slips through to the network.

If you find a bypass, an incorrect restoration (data loss or duplication), or any other security issue, please report it privately:

- Email: **security@veil.dev** (replace with your project's address)
- Or open a private security advisory on GitHub: `Security` → `Report a vulnerability`.

Please include, when possible:

1. The exact input that bypasses redaction (or restores incorrectly).
2. The categories configured (`default`, `all`, or an explicit list).
3. The environment (Node/Bun/Deno/browser + version).
4. A minimal reproduction.

We aim to acknowledge within 72 hours and to ship a fix within 14 days for confirmed bypasses.

## Disclosure timing

We prefer coordinated disclosure. Once a fix is released we will publish a security advisory and credit the reporter (unless they prefer to remain anonymous).

## What is in scope

- **Redaction bypass:** a sensitive value that reaches the request body, URL query, or (opt-in) header in cleartext.
- **Restoration defect:** a token that restores to the wrong value, or a streaming restore that drops/duplicates bytes.
- **State leakage:** the token↔original map being exposed, persisted, or sent off-process.
- **Cross-talk:** one fetch call's tokens being restored into another call's response.

## What is out of scope

- The provider logging the *tokenized* payload. That is the intended behavior; tokens are opaque and carry no PII.
- Redaction of content-types `veil` is explicitly configured to skip (binary, non-text).
- Attacks on the underlying platform's `fetch` implementation.

## Bypass bounty

We maintain a list of known, fixed bypasses in `CHANGELOG.md` under the relevant versions. If you're fuzzing the redactor, the corpus snapshot tests in `packages/core/test/corpus.test.ts` are a good starting point.
