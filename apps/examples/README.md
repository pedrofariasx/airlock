# Examples

Runnable examples for `veil`. Each file is self-contained and uses an in-process
fake upstream so it runs without a real server or API key.

## Run

From the repo root (after `npm install`):

```sh
npm run custom-api           # arbitrary untrusted API (the primary use case)
npm run openai-stream        # OpenAI-compatible streaming completion
npm run anthropic            # Anthropic-style messages endpoint
npm run express-middleware   # Express server proxying outbound calls
```

Or directly from this directory:

```sh
node --import tsx custom-api.ts
```

## What each shows

- **`custom-api.ts`** — the universal case. veil knows nothing about the
  endpoint's schema. It redacts every string in the JSON body and restores the
  response. This is the pattern to copy for any arbitrary HTTP API.
- **`openai-stream.ts`** — an OpenAI-compatible streaming (`stream: true`)
  completion. The SSE response is restored chunk by chunk, including a token
  split across chunks.
- **`anthropic.ts`** — an Anthropic-style `/v1/messages` call (non-streaming).
- **`express-middleware.ts`** — a server that proxies outbound calls to an
  untrusted upstream, with veil installed once at boot.

## Python / curl / non-JS

For non-JS clients, use the `veil-proxy` CLI companion (ships later in the
roadmap):

```sh
npx veil-proxy --upstream https://api.untrusted-upstream.com --port 8787
REDACT_PII=1
```

Then point your Python/curl/IDE client at `http://localhost:8787`:

```python
# Python via the proxy
import requests
r = requests.post(
    "http://localhost:8787/v1/work",
    json={"customer": {"email": "alice@example.com"}},
)
print(r.json())   # restored in-process by the proxy
```

```sh
# curl via the proxy
curl -s http://localhost:8787/v1/work \
  -H 'content-type: application/json' \
  -d '{"customer":{"email":"alice@example.com"}}'
```
