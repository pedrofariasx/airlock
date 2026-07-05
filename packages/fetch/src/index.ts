// @airlock/fetch — universal redacting fetch wrapper.
//
// Wraps globalThis.fetch. For every matching call it builds ONE Redactor
// (request side) + Restorer (response side) pair in a closure, so tokens
// minted in the request are known when restoring the response. No global
// state survives the call.

import {
  ALL_CATEGORIES,
  DEFAULT_CATEGORIES,
  RedactCategory,
  Redactor,
  Restorer,
} from '@airlock/core';

export interface RedactFetchOptions {
  /**
   * Which URLs to redact. Default: all. A glob like
   * `https://upstream.example.com/**`, an array of globs, or a predicate.
   */
  urls?: string | string[] | ((url: string) => boolean);
  /** Categories to redact. Default: DEFAULT_CATEGORIES. `'all'` for opt-in too. */
  categories?: readonly RedactCategory[] | 'all' | 'default';
  /** What to redact in the request. */
  request?: {
    body?: boolean;
    urlQuery?: boolean;
    /** Default OFF. When ON, only redact values of headers listed by name. */
    headers?: boolean | string[] | { allow?: string[] };
  };
  /** What to restore in the response, by content-type. */
  response?: {
    /**
     * Content-type prefixes to restore. Default restores text/*, JSON, SSE.
     * Pass an explicit array to override.
     */
    types?: string[];
  };
}

const DEFAULT_RESPONSE_TYPES = ['text/', 'application/json', 'text/event-stream'];

const DEFAULT_OPTS: Required<Pick<RedactFetchOptions, 'request' | 'response'>> & {
  // resolved later
} = {
  request: { body: true, urlQuery: true, headers: false },
  response: { types: DEFAULT_RESPONSE_TYPES },
} as any;

// ---------------------------------------------------------------------------
// Glob matching
// ---------------------------------------------------------------------------

/** Compile a glob into a predicate. Supports `**` and `*` (single segment). */
function globToRe(glob: string): RegExp {
  // Escape regex specials except * and /.
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++; // consume second '*'
        // optional trailing slash
        if (glob[i + 1] === '/') {
          // allow **/ to match zero or more segments
          re += '(?:/.*)?';
          i++;
        }
      } else {
        re += '[^/]*';
      }
    } else if ('.+?^${}()|[]\\'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  return new RegExp('^' + re + '$');
}

function matchUrlFilter(
  url: string,
  filter: NonNullable<RedactFetchOptions['urls']>,
): boolean {
  if (typeof filter === 'function') return filter(url);
  const globs = Array.isArray(filter) ? filter : [filter];
  // Always operate on the URL without fragment for matching.
  const u = url.split('#')[0]!;
  for (const g of globs) {
    if (g === '' ) continue;
    if (globToRe(g).test(u)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// URL query redaction
// ---------------------------------------------------------------------------

/** Redact query string values, preserving path and structure. */
function redactUrl(url: string, redactor: Redactor): string {
  const hashIdx = url.indexOf('#');
  let main = url;
  let hash = '';
  if (hashIdx >= 0) {
    main = url.slice(0, hashIdx);
    hash = url.slice(hashIdx);
  }
  const qIdx = main.indexOf('?');
  if (qIdx < 0) return url;
  const base = main.slice(0, qIdx);
  const query = main.slice(qIdx + 1);
  if (query === '') return url;
  const pairs = query.split('&');
  const out: string[] = [];
  for (const p of pairs) {
    const eq = p.indexOf('=');
    if (eq < 0) {
      // flag-style param, no value
      out.push(p);
      continue;
    }
    const key = p.slice(0, eq);
    const val = p.slice(eq + 1);
    // Decode, redact, re-encode. Preserve encoding style roughly.
    const decoded = safeDecodeURIComponent(val);
    const redacted = redactor.redact(decoded);
    out.push(key + '=' + encodeURIComponent(redacted));
  }
  return base + '?' + out.join('&') + hash;
}

function safeDecodeURIComponent(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

// ---------------------------------------------------------------------------
// Request body redaction
// ---------------------------------------------------------------------------

/**
 * Decide whether a body is text-like and should be redacted. Returns the
 * textual representation to redact, or null for binary bodies.
 */
type BodyKind = 'json' | 'text' | 'form' | 'search' | 'stream' | 'binary' | 'none';

function classifyBody(body: any, contentType: string): BodyKind {
  if (body == null || body === '') return 'none';
  if (body instanceof ReadableStream) return 'stream';
  if (typeof body === 'string') {
    if (isJsonType(contentType) || looksLikeJson(body)) return 'json';
    return 'text';
  }
  // Web APIs
  if (typeof FormData !== 'undefined' && body instanceof FormData) return 'form';
  if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams)
    return 'search';
  if (typeof Blob !== 'undefined' && body instanceof Blob) {
    return isTextType(body.type) ? 'text' : 'binary';
  }
  if (typeof ArrayBuffer !== 'undefined' && body instanceof ArrayBuffer) return 'binary';
  if (ArrayBuffer.isView(body)) return 'binary';
  return 'binary';
}

function isJsonType(ct: string): boolean {
  return ct.includes('application/json') || ct.includes('+json');
}

function isTextType(ct: string): boolean {
  return ct.startsWith('text/') || isJsonType(ct) || ct.includes('text/event-stream');
}

function looksLikeJson(s: string): boolean {
  const t = s.trimStart();
  return t[0] === '{' || t[0] === '[';
}

/** Recursively walk a JSON value and redact every string. */
function redactJson(value: any, redactor: Redactor): any {
  if (typeof value === 'string') return redactor.redact(value);
  if (Array.isArray(value)) return value.map((v) => redactJson(v, redactor));
  if (value && typeof value === 'object') {
    const out: Record<string, any> = {};
    for (const k of Object.keys(value)) {
      out[k] = redactJson((value as any)[k], redactor);
    }
    return out;
  }
  return value;
}

/** Redact string values of a FormData, returning a new FormData. */
function redactFormData(body: FormData, redactor: Redactor): FormData {
  const out = new FormData();
  for (const [key, val] of body.entries()) {
    if (typeof val === 'string') out.append(key, redactor.redact(val));
    else out.append(key, val); // Blob/File passthrough
  }
  return out;
}

/** Redact string values of URLSearchParams. */
function redactSearchParams(body: URLSearchParams, redactor: Redactor): URLSearchParams {
  const out = new URLSearchParams();
  for (const [key, val] of body.entries()) {
    out.append(key, redactor.redact(val));
  }
  return out;
}

/** Wrap a ReadableStream<Uint8Array> with a redacting TransformStream. */
function redactStream(body: ReadableStream<Uint8Array>, redactor: Redactor): ReadableStream<Uint8Array> {
  const decoder = new TextDecoder('utf-8');
  const encoder = new TextEncoder();
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        const text = decoder.decode(chunk, { stream: true });
        const redacted = redactor.redact(text);
        controller.enqueue(encoder.encode(redacted));
      },
      flush() {
        // Nothing to flush on the redactor side; it is stateless per call but
        // stable tokens are already minted via the redactor.map.
        void decoder.decode(new Uint8Array(0));
      },
    }),
  );
}

// ---------------------------------------------------------------------------
// Response restoration
// ---------------------------------------------------------------------------

/** True if a content-type should be restored. */
function shouldRestore(ct: string, types: string[]): boolean {
  const lower = (ct || '').toLowerCase();
  for (const t of types) {
    if (lower.startsWith(t.toLowerCase())) return true;
  }
  return false;
}

/**
 * Wrap a Response so its body is restored. For text/json we buffer, restore,
 * and rebuild. For SSE we pipe through a restoring TransformStream using the
 * shared Restorer. For non-text we pass the body through untouched.
 */
function wrapResponse(
  response: Response,
  restorer: Restorer,
  types: string[],
): Response {
  const ct = response.headers.get('content-type') || '';
  if (!shouldRestore(ct, types)) {
    return response; // binary/other: passthrough
  }

  const isSSE = ct.includes('text/event-stream');
  if (isSSE && response.body) {
    const restoredBody = pipeRestore(response.body, restorer);
    return rebuildResponse(response, restoredBody);
  }

  // For non-streaming text/json: clone the body, restore, rebuild.
  // We must consume the original body once.
  return new Response(
    new ReadableStream<Uint8Array>({
      async start(controller) {
        try {
          const buf = await response.arrayBuffer();
          const text = new TextDecoder('utf-8').decode(new Uint8Array(buf));
          const restored = restorer.push(text) + restorer.flush();
          controller.enqueue(new TextEncoder().encode(restored));
        } catch (e) {
          controller.error(e as any);
          return;
        }
        controller.close();
      },
    }),
    {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    },
  );
}

/** Pipe a byte stream through a Restorer using TextDecoder/Encoder. */
function pipeRestore(
  body: ReadableStream<Uint8Array>,
  restorer: Restorer,
): ReadableStream<Uint8Array> {
  const decoder = new TextDecoder('utf-8');
  const encoder = new TextEncoder();
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        const text = decoder.decode(chunk, { stream: true });
        const out = restorer.push(text);
        if (out) controller.enqueue(encoder.encode(out));
      },
      flush(controller) {
        const tail = decoder.decode(); // finalize decoder
        const out = restorer.push(tail) + restorer.flush();
        if (out) controller.enqueue(encoder.encode(out));
      },
    }),
  );
}

/** Rebuild a Response preserving status/headers but swapping the body. */
function rebuildResponse(response: Response, body: ReadableStream<Uint8Array>): Response {
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

/**
 * Install the redacting fetch wrapper on globalThis.fetch. Returns an
 * uninstall function that restores the original fetch. Reentrant and
 * idempotent: installing twice wraps once and the second uninstall restores
 * correctly.
 */
export function installRedactFetch(options: RedactFetchOptions = {}): () => void {
  const cats = options.categories ?? 'default';
  const categories = cats === 'all' ? ALL_CATEGORIES : cats === 'default' ? DEFAULT_CATEGORIES : cats;

  const reqOpts = {
    body: options.request?.body ?? true,
    urlQuery: options.request?.urlQuery ?? true,
    headers: options.request?.headers ?? false,
  };
  const resTypes = options.response?.types ?? DEFAULT_RESPONSE_TYPES;
  const urlFilter = options.urls; // undefined => all

  const originalFetch = globalThis.fetch as typeof fetch;
  // If already wrapped, do not double-wrap. We tag the function.
  if ((originalFetch as any).__airlockWrapped) {
    return () => {}; // already installed; no-op uninstall
  }

  const wrappedFetch: typeof fetch = async (input, init) => {
    // Resolve the URL string for filtering.
    const urlStr = typeof input === 'string' ? input : (input as URL).toString();
    const shouldRedact = urlFilter ? matchUrlFilter(urlStr, urlFilter) : true;

    if (!shouldRedact) {
      return originalFetch(input, init);
    }

    // One Redactor/Restorer pair per call.
    const redactor = new Redactor({ categories });
    const restorer = redactor.buildRestorer();

    // --- Request side ---
    let newInit = init;
    let newInput: RequestInfo | URL = input;

    // URL query
    if (reqOpts.urlQuery) {
      const redactedUrl = redactUrl(urlStr, redactor);
      if (redactedUrl !== urlStr) {
        if (typeof input === 'string') newInput = redactedUrl;
        else newInput = redactedUrl; // URL/string both accepted as string
      }
    }

    // Headers
    if (reqOpts.headers) {
      const allowedHeaderNames = resolveAllowedHeaders(reqOpts.headers);
      if (allowedHeaderNames.length > 0 && init && init.headers) {
        const headers = new Headers(init.headers);
        for (const name of allowedHeaderNames) {
          const val = headers.get(name);
          if (val !== null && val !== '') {
            headers.set(name, redactor.redact(val));
          }
        }
        newInit = { ...(init as RequestInit), headers };
      }
    }

    // Body
    if (reqOpts.body && init && init.body != null) {
      const ct = (init.headers as any) instanceof Headers
        ? (init.headers as Headers).get('content-type') || ''
        : (init && (init as RequestInit).headers && typeof (init as RequestInit).headers === 'object' && !Array.isArray((init as RequestInit).headers))
          ? ((init as RequestInit).headers as Record<string, string>)?.['content-type'] || ((init as RequestInit).headers as Record<string, string>)?.['Content-Type'] || ''
          : '';
      const kind = classifyBody(init.body, ct || '');
      const base: RequestInit = (newInit as RequestInit) ?? (init as RequestInit);
      switch (kind) {
        case 'none':
          break;
        case 'json': {
          if (typeof init.body === 'string') {
            try {
              const parsed = JSON.parse(init.body as string);
              const redacted = redactJson(parsed, redactor);
              newInit = { ...base, body: JSON.stringify(redacted) };
            } catch {
              // Not valid JSON despite looks; treat as text.
              newInit = { ...base, body: redactor.redact(init.body as string) };
            }
          } else {
            newInit = { ...base, body: JSON.stringify(redactJson(init.body, redactor)) };
          }
          break;
        }
        case 'text':
          newInit = { ...base, body: redactor.redact(init.body as string) };
          break;
        case 'form':
          newInit = { ...base, body: redactFormData(init.body as FormData, redactor) };
          break;
        case 'search':
          newInit = { ...base, body: redactSearchParams(init.body as URLSearchParams, redactor) };
          break;
        case 'stream':
          newInit = { ...base, body: redactStream(init.body as ReadableStream<Uint8Array>, redactor) };
          break;
        case 'binary':
        default:
          // pass through untouched
          break;
      }
    }

    // --- Call upstream ---
    const response = await originalFetch(newInput, newInit);

    // --- Response side ---
    return wrapResponse(response, restorer, resTypes);
  };

  (wrappedFetch as any).__airlockWrapped = true;
  (wrappedFetch as any).__airlockOriginal = originalFetch;

  globalThis.fetch = wrappedFetch as typeof fetch;

  return () => {
    if (globalThis.fetch === wrappedFetch) {
      globalThis.fetch = originalFetch;
    }
  };
}

function resolveAllowedHeaders(headers: NonNullable<NonNullable<RedactFetchOptions['request']>>['headers']): string[] {
  if (!headers) return [];
  if (typeof headers === 'boolean') return [];
  if (Array.isArray(headers)) return headers.map((h) => h.toLowerCase());
  if (typeof headers === 'object' && headers && 'allow' in headers) {
    return (headers.allow ?? []).map((h: string) => h.toLowerCase());
  }
  return [];
}
