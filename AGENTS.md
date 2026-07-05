# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

`veil` is a reversible redaction library for calling any HTTP API on an
untrusted provider without leaking PII/secrets. Library-first; the `fetch`
wrapper is the primary product.

## Layout

- `packages/core` — pure redaction engine (`@veil/core`). Zero deps, isomorphic.
  Only standard Web APIs allowed. No Node-only APIs here.
- `packages/fetch` — universal `installRedactFetch` wrapper (`@veil/fetch`).
  Depends on `@veil/core`. Web Streams / fetch only.
- `apps/examples` — runnable examples.
- `apps/docs` — docs source (placeholder).

## Non-negotiables

1. `core` must stay zero-dependency and isomorphic.
2. No telemetry, no network calls, no persisted state.
3. Prefer false-negatives over masking prose in opt-in categories.
4. Restoration is byte-exact; streaming restore must never drop/duplicate bytes.
5. No global mutable state across fetch calls.

## Commands

```sh
npm install
npm run typecheck   # all workspaces
npm run build       # all workspaces -> dist/
npm test            # node:test, all workspaces
npm run test:coverage  # c8, must stay >=90% on core & fetch
```

Per-package (from `packages/<name>`): `npm run build`, `npm test`,
`npm run test:coverage`.

## Adding a category

1. Add the scanner in `packages/core/src/categories.ts` in the right
   position (specific/long before generic).
2. Add/ wire a validator in `packages/core/src/validators.ts` if there is a
   checksum.
3. Add to `DEFAULT_CATEGORIES` or `OPT_IN_CATEGORIES` in `categories.ts`.
4. Add valid + invalid tests in `packages/core/test/core.test.ts`.
5. Add a corpus entry in `packages/core/test/corpus.test.ts`.

## Commits & releases

Conventional Commits + Changesets. Use `npx changeset` to describe a change.
Do not publish manually; CI publishes on tag.

## Security

Redaction bypass = security bug. See `SECURITY.md`. Add a regression test that
fails without any bypass fix.
