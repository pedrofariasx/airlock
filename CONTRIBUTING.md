# Contributing

Thanks for considering a contribution to `Airlock`. This is a security-sensitive library, so a few extra rules apply.

## Setup

```sh
git clone <repo>
cd airlock
npm install
npm run build
npm test
```

The repo is a npm workspaces monorepo:

- `packages/core` — the pure redaction engine (`@airlock/core`). Zero deps, isomorphic.
- `packages/fetch` — the universal fetch wrapper (`@airlock/fetch`). Depends on `@airlock/core`.
- `apps/examples` — runnable examples.

## Non-negotiables

1. **`core` stays zero-dependency and isomorphic.** Only standard Web APIs. No Node-only APIs in `core`.
2. **No telemetry, no network calls, no persisted state.** Ever.
3. **Prefer false-negatives over masking prose** in opt-in categories. A missed CPF is better than a masked sentence.
4. **Restoration is byte-exact.** Never lose or duplicate a byte in streaming restore.
5. **No global mutable state.** Each fetch call gets its own `Redactor`/`Restorer`.

## Adding or changing a category

A category is a scanner (regex or function) + a validator + a token name. See `packages/core/src/categories.ts`.

- Add the scanner to `SCANNERS` in the right position (specific/long patterns before generic ones).
- If the category has a checksum, implement the validator in `validators.ts` and wire it.
- If the category is high-false-positive, mark it `optIn: true` and add it to `OPT_IN_CATEGORIES`, **not** `DEFAULT_CATEGORIES`.
- Add tests for valid and invalid cases in `packages/core/test/core.test.ts`.

## Tests

- Every change to `core` or `fetch` must keep `npm test` green.
- Coverage must stay ≥90% on both `core` and `fetch`:
  ```sh
  npm run test:coverage --workspaces --if-present
  ```
- Add a corpus entry to `packages/core/test/corpus.test.ts` when you add a category.
- For `fetch` changes, add an integration test with a mock fetch (see `packages/fetch/test/`).

## Commits & releases

We use [Conventional Commits](https://www.conventionalcommits.org/) and [Changesets](https://github.com/changesets/changesets):

```sh
npx changeset        # describe your change
git commit -m "feat(core): add pis validator"
```

Releases are produced by the CI on tag. Do not publish manually.

## Security-relevant changes

If your change affects what gets redacted or how it's restored, open a PR and flag it for review. Bypass fixes should reference `SECURITY.md`. Add regression tests that would fail without the fix.

## License

By contributing you agree your contributions are licensed under the project's MIT license.
