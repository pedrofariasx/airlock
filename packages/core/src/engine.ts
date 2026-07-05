// Redactor + Restorer: the reversible redaction engine.

import {
  DEFAULT_CATEGORIES,
  ALL_CATEGORIES,
  Match,
  RedactCategory,
  scannersFor,
  Scanner,
} from './categories.js';

export interface RedactorOptions {
  categories?: readonly RedactCategory[] | 'all' | 'default';
}

interface CategoryState {
  scanner: Scanner;
  /** value → counter index (1-based) */
  seen: Map<string, number>;
  count: number;
}

/**
 * Redactor holds the live token↔value mapping for a single redaction session
 * (e.g. one fetch request/response pair). It is stateful but purely in-memory
 * and has no global state: create one per call.
 */
export class Redactor {
  private readonly scanners: Scanner[];
  private readonly states = new Map<RedactCategory, CategoryState>();
  /** token → original value, shared with the Restorer built from this Redactor. */
  readonly map = new Map<string, string>();

  constructor(categories: RedactorOptions = {}) {
    const cats = resolveCategories(categories.categories);
    this.scanners = scannersFor(cats);
    for (const s of this.scanners) {
      this.states.set(s.category, { scanner: s, seen: new Map(), count: 0 });
    }
  }

  /**
   * Redact all sensitive spans in `text`, replacing them with stable opaque
   * tokens. The same value always maps to the same token within this Redactor.
   */
  redact(text: string): string {
    // Gather matches across all scanners.
    const all: Match[] = [];
    for (const s of this.scanners) {
      const ms = s.scan(text);
      for (const m of ms) all.push(m);
    }
    if (all.length === 0) return text;

    // Resolve overlaps: keep the longer/more-specific span at any point. When
    // two spans overlap, the one that appears earlier in SCANNERS order wins
    // on ties (specific-first ordering).
    all.sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      const lenDiff = b.end - b.start - (a.end - a.start);
      if (lenDiff !== 0) return lenDiff;
      return scannerOrder(a.category) - scannerOrder(b.category);
    });

    const canonical: Match[] = [];
    let lastEnd = -1;
    for (const m of all) {
      if (m.start >= lastEnd) {
        canonical.push(m);
        lastEnd = m.end;
      } else {
        // Overlap: keep the one already chosen if it extends further; otherwise
        // replace (this can happen because we sorted by start then by length
        // descending).
        const prev = canonical[canonical.length - 1];
        if (prev && m.end > prev.end && m.start === prev.start) {
          canonical[canonical.length - 1] = m;
          lastEnd = m.end;
        }
      }
    }

    // Build output, inserting tokens. Process right-to-left to preserve indices.
    let out = text;
    for (let i = canonical.length - 1; i >= 0; i--) {
      const m = canonical[i];
      if (!m) continue;
      const token = this.tokenFor(m);
      out = out.slice(0, m.start) + token + out.slice(m.end);
    }
    return out;
  }

  private tokenFor(m: Match): string {
    const st = this.states.get(m.category);
    if (!st) return m.value; // unreachable
    let idx = st.seen.get(m.value);
    if (idx === undefined) {
      st.count += 1;
      idx = st.count;
      st.seen.set(m.value, idx);
      const token = `<<PII_${st.scanner.token}_${idx}>>`;
      this.map.set(token, m.value);
      return token;
    }
    return `<<PII_${st.scanner.token}_${idx}>>`;
  }

  /** Build a Restorer bound to this Redactor's token map. */
  buildRestorer(): Restorer {
    return new Restorer(this.map);
  }
}

/**
 * Restorer reverses redaction in a streaming-safe way. It maintains a carry
 * buffer so tokens split across chunks are restored only once fully seen.
 */
export class Restorer {
  private readonly map: Map<string, string>;
  private carry = '';
  /** True once flush() has been called. */
  private done = false;

  constructor(map: Map<string, string>) {
    this.map = map;
  }

  /**
   * Push a chunk of redacted text and return the restored portion that can be
   * emitted now. A token that straddles the chunk boundary is held in the
   * carry buffer until it completes (in a later push) or until flush().
   */
  push(chunk: string): string {
    if (this.done) {
      throw new Error('Restorer.push called after flush');
    }
    const buf = this.carry + chunk;
    const { out, rest } = this.restoreInternal(buf, /*end*/ false);
    this.carry = rest;
    return out;
  }

  /** Restore a full string at once (non-streaming convenience). */
  restoreAll(s: string): string {
    const { out } = this.restoreInternal(s, /*end*/ true);
    return out;
  }

  /** Flush any remaining carry buffer, forcing pending tokens to resolve. */
  flush(): string {
    if (this.done) return '';
    this.done = true;
    const buf = this.carry;
    this.carry = '';
    const { out } = this.restoreInternal(buf, /*end*/ true);
    return out;
  }

  /**
   * Core restore pass over `buf`.
   * - When `end` is false, the tail of `buf` might be the prefix of a token;
   *   we hold it back as `rest`.
   * - When `end` is true, we process everything; any leftover `<<` that is not
   *   a known token is emitted verbatim.
   */
  private restoreInternal(buf: string, end: boolean): { out: string; rest: string } {
    let out = '';
    let i = 0;
    while (i < buf.length) {
      const lt = buf.indexOf('<<', i);
      if (lt === -1) {
        const tail = buf.slice(i);
        if (!end && tail.length > 0) {
          // Hold back a trailing run of '<' characters that could be the
          // start of a '<<' token marker. Any other text is safe to emit.
          const ltRun = trailingLtRun(tail);
          if (ltRun > 0) {
            out += tail.slice(0, tail.length - ltRun);
            return { out, rest: tail.slice(tail.length - ltRun) };
          }
        }
        out += tail;
        i = buf.length;
        break;
      }
      // emit text before the token marker
      out += buf.slice(i, lt);

      const gt = buf.indexOf('>>', lt + 2);
      if (gt === -1) {
        // No closing marker yet.
        if (end) {
          // No token here; emit the '<<' literally and continue scanning the
          // rest (which may contain more text).
          out += '<<';
          i = lt + 2;
          continue;
        }
        // Hold back from '<<' to end as a potential partial token. We hold
        // back any '<<' followed by characters that could still extend into
        // a known token shape (`<<PII_..._n>>`). If the text after '<<' already
        // contains a character that cannot be part of a token (e.g. a space,
        // lowercase, or another '<<'), it is not a token prefix and we emit
        // the '<<' literally.
        const tail = buf.slice(lt);
        if (couldBeTokenPrefix(tail)) {
          return { out, rest: tail };
        }
        out += '<<';
        i = lt + 2;
        continue;
      }

      const candidate = buf.slice(lt, gt + 2);
      const original = this.map.get(candidate);
      if (original !== undefined) {
        out += original;
        i = gt + 2;
        continue;
      }

      // Not a known token. If we are at the very end (end=true) emit literally.
      if (end) {
        out += candidate;
        i = gt + 2;
        continue;
      }

      // Not at end: but the closing '>>' is present, so it is definitely not
      // a token we know. Emit literally and continue.
      out += candidate;
      i = gt + 2;
    }

    return { out, rest: '' };
  }
}

/** Number of trailing '<' chars that could be the start of a '<<' marker. */
function trailingLtRun(tail: string): number {
  let n = 0;
  for (let i = tail.length - 1; i >= 0; i--) {
    if (tail[i] === '<') n++;
    else break;
  }
  // Only a single trailing '<' could become '<<' (two would already be a
  // marker and handled elsewhere). Cap at 1.
  return Math.min(n, 1);
}

/**
 * True if `tail` (starting with '<<') could be a prefix of a token like
 * `<<PII_EMAIL_1>>`. We accept partial forms such as `<<`, `<<P`, `<<PI`,
 * `<<PII`, `<<PII_`, `<<PII_E`, `<<PII_EMAIL_1`, and `<<PII_EMAIL_1>` as long
 * as the body after `<<` is composed only of [A-Z0-9_] optionally followed by
 * a single trailing `>` (the start of `>>`). A space, lowercase, or another
 * `<<` disqualifies.
 */
function couldBeTokenPrefix(tail: string): boolean {
  if (!tail.startsWith('<<')) return false;
  if (tail.includes('>>')) return false;
  let after = tail.slice(2);
  // Allow a single trailing '>' (could become '>>').
  let trailingGt = 0;
  if (after.endsWith('>')) {
    trailingGt = 1;
    after = after.slice(0, -1);
  }
  for (let i = 0; i < after.length; i++) {
    const c = after.charCodeAt(i);
    const ok =
      (c >= 65 && c <= 90) || // A-Z
      (c >= 48 && c <= 57) || // 0-9
      c === 95; // _
    if (!ok) return false;
  }
  return true;
}

function resolveCategories(
  c: RedactorOptions['categories'],
): readonly RedactCategory[] {
  if (!c || c === 'default') {
    return DEFAULT_CATEGORIES;
  }
  if (c === 'all') return ALL_CATEGORIES;
  return c;
}

function scannerOrder(cat: RedactCategory): number {
  // Lower = higher priority on ties. Mirrors SCANNERS order.
  const order: RedactCategory[] = [
    'privatekey',
    'dburl',
    'jwt',
    'aws',
    'apikey',
    'email',
    'phone',
    'cpf',
    'cnpj',
    'card',
    'token',
    'ip',
    'mac',
    'cep',
    'pis',
    'ssn',
  ];
  return order.indexOf(cat);
}
