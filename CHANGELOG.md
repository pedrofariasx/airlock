# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `@veil/core` 0.1.0: pure reversible redaction engine with `Redactor` / `Restorer`.
  - Default categories: `email`, `phone`, `cpf`, `cnpj`, `apikey`, `card`,
    `dburl`, `jwt`, `privatekey`, `aws`, `token`.
  - Opt-in categories: `ip`, `mac`, `cep`, `pis`, `ssn`.
  - Real validators: CPF, CNPJ, PIS, SSN, CEP, IPv4, Luhn, AWS secret, JWT.
  - Non-overlap resolution: specific/long patterns win over generic ones.
  - Streaming-safe `Restorer` with lookahead for tokens split across chunks.
- `@veil/fetch` 0.1.0: universal `installRedactFetch` wrapper around
  `globalThis.fetch`.
  - Redacts JSON / string / `FormData` / `URLSearchParams` / streaming request
    bodies; binary bodies pass through.
  - Redacts URL query-string values; path is never touched.
  - Headers off by default; opt-in with explicit allow-list only.
  - Restores `text/*`, `application/json`, and `text/event-stream` responses;
    non-text responses pass through.
  - One `Redactor`/`Restorer` pair per call (no cross-talk, no global state).
  - Idempotent install / uninstall.
- Repository scaffolding: npm workspaces, TypeScript, `node:test`, `c8`
  coverage, Conventional Commits, Changesets.
