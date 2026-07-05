// Category definitions: patterns + validators + token naming.
// Order matters for non-overlap resolution: longer/more specific patterns
// are matched first and consume their canonical span before generic ones run.

import {
  awsSecretValid,
  cepValid,
  cnpjValid,
  cpfValid,
  ipv4Valid,
  jwtValid,
  luhnValid,
  pisValid,
  ssnValid,
} from './validators.js';

export type RedactCategory =
  | 'email'
  | 'phone'
  | 'cpf'
  | 'cnpj'
  | 'apikey'
  | 'card'
  | 'dburl'
  | 'jwt'
  | 'privatekey'
  | 'aws'
  | 'ip'
  | 'mac'
  | 'cep'
  | 'pis'
  | 'ssn'
  | 'token';

/** A single match candidate produced by a category's scanner. */
export interface Match {
  category: RedactCategory;
  start: number;
  end: number;
  /** The captured sensitive value (only the value part for keyword tokens). */
  value: string;
}

/**
 * Scanner specification for a category. Either a regex with capture groups
 * (the last group is the value) or a function returning matches.
 */
export interface Scanner {
  category: RedactCategory;
  /** Stable token prefix, e.g. `EMAIL` → `<<PII_EMAIL_1>>`. */
  token: string;
  scan: (text: string) => Match[];
  /** Optional human-readable label for docs. */
  label: string;
  /** Whether this is an opt-in (high false-positive) category. */
  optIn?: boolean;
}

/** Build a regex-based scanner. The last capture group is the value. */
function regexScanner(
  category: RedactCategory,
  token: string,
  re: RegExp,
  opts: { label: string; optIn?: boolean; validator?: (v: string) => boolean },
): Scanner {
  return {
    category,
    token,
    label: opts.label,
    optIn: opts.optIn,
    scan(text: string): Match[] {
      const out: Match[] = [];
      // Use matchAll with the global regex. We re-clone to avoid lastIndex
      // statefulness across calls.
      const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
      for (const m of text.matchAll(g)) {
        if (m.index === undefined) continue;
        // The value is the last defined capture group, else the whole match.
        let value = m[0];
        let start = m.index;
        let end = m.index + m[0].length;
        for (let gi = m.length - 1; gi >= 1; gi--) {
          if (m[gi] !== undefined) {
            value = m[gi] as string;
            // start of the capture group within the string
            const groupIndex = indexOfGroup(text, m[0], m.index, gi, m);
            start = groupIndex;
            end = groupIndex + value.length;
            break;
          }
        }
        if (opts.validator && !opts.validator(value)) continue;
        out.push({ category, start, end, value });
      }
      return out;
    },
  };
}

/** Compute the absolute index of capture group `group` in `text`. */
function indexOfGroup(
  text: string,
  whole: string,
  wholeIndex: number,
  group: number,
  match: RegExpMatchArray,
): number {
  // Walk through the whole match and the match array to find the offset.
  // We rely on the fact that capture groups appear in order; find the start
  // by reconstructing from the regex's group positions via match.indices if
  // available (the 'd' flag), otherwise fall back to indexOf.
  const indices = (match as any).indices;
  if (indices && indices[group]) {
    return indices[group][0] as number;
  }
  // Fallback: search for the group value within the whole match. This is
  // imperfect if the value repeats, but we only use it when 'd' is absent.
  const rel = whole.indexOf(match[group] as string);
  return wholeIndex + (rel < 0 ? 0 : rel);
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

// Email: local-part@domain. Conservative local-part to reduce FP.
const EMAIL_RE = /\b([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24})\b/g;

// Phone: require an explicit phone indicator — a leading '+' (E.164) or a
// parenthesized area code like (11) — to avoid swallowing validated digit
// tokens (CPF/CNPJ/card/CEP/IP) that also use separators. This is the
// low-false-positive choice per the project principles.
const PHONE_RE =
  /(?<![A-Za-z0-9])(\+\d{1,3}[\s.-]?\(?\d+\)?[\d\s().-]{4,}\d|\(\d{2,3}\)[\s.-]?\d{4,}[\s.-]?\d{3,4})(?![A-Za-z0-9])/g;

// CPF: 000.000.000-00 or 11 raw digits (when validated).
const CPF_RE = /\b(\d{3}\.?\d{3}\.?\d{3}-?\d{2})\b/g;

// CNPJ: 00.000.000/0000-00 or 14 raw digits (validated).
const CNPJ_RE = /\b(\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2})\b/g;

// Credit card: 13-19 digits with optional separators, validated by Luhn.
const CARD_RE = /\b(\d{4}[\s-]?\d{4,6}[\s-]?\d{4,6}[\s-]?\d{0,5}\d)\b/g;

// API key: common prefixes + 20+ base64-ish chars.
const APIKEY_RE =
  /\b(sk-[A-Za-z0-9_-]{20,}|pk-[A-Za-z0-9_-]{20,}|sk_(?:live|test|proj)_[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|api[_-]?key[_-]?[A-Za-z0-9_-]{16,})\b/g;

// Database URL: scheme://user(:pass)?@host/db
const DBURL_RE =
  /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|cassandra|mssql|jdbc:[a-z]+):\/\/[^\s"'<>`]{4,})/gi;

// JWT: three base64url segments.
const JWT_RE = /\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g;

// PEM private key block.
const PRIVATEKEY_RE =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g;

// AWS secret: 40 base64-ish chars. Opt-in via validator entropy.
const AWS_RE = /\b([A-Za-z0-9/+]{40})\b/g;

// Keyword-bearer token: redact only the value after the keyword. "Bearer"
// is followed by a space; the others (token/api_key/Authorization) by '=' or
// ':'. The value is an opaque credential run.
const TOKEN_RE =
  /(?<=\b(?:Bearer\s|(?:token|api_key|apikey|access_token|refresh_token|Authorization)\s*[=:]\s*))([A-Za-z0-9._~+\/-]{8,})\b/gi;

// IPv4 (opt-in).
const IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

// MAC address (opt-in).
const MAC_RE = /\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b/g;

// CEP (opt-in).
const CEP_RE = /\b(\d{5}-\d{3})\b/g;

// PIS (opt-in).
const PIS_RE = /\b(\d{3}\.?\d{5}\.?\d{2}-?\d)\b/g;

// SSN (opt-in): 123-45-6789 or 9 digits.
const SSN_RE = /\b(\d{3}-\d{2}-\d{4})\b/g;

// ---------------------------------------------------------------------------
// Scanners, ordered: specific/long first, generic apikey/token last.
// ---------------------------------------------------------------------------

export const SCANNERS: Scanner[] = [
  regexScanner('privatekey', 'PRIVATEKEY', PRIVATEKEY_RE, { label: 'PEM private key block' }),
  regexScanner('dburl', 'DBURL', DBURL_RE, { label: 'Database connection URL' }),
  regexScanner('jwt', 'JWT', JWT_RE, { label: 'JWT', validator: jwtValid }),
  regexScanner('aws', 'AWS', AWS_RE, { label: 'AWS secret access key', validator: awsSecretValid }),
  regexScanner('apikey', 'APIKEY', APIKEY_RE, { label: 'API key (known prefixes)' }),
  regexScanner('email', 'EMAIL', EMAIL_RE, { label: 'Email address' }),
  regexScanner('phone', 'PHONE', PHONE_RE, { label: 'Phone number' }),
  regexScanner('cpf', 'CPF', CPF_RE, { label: 'Brazilian CPF', validator: cpfValid }),
  regexScanner('cnpj', 'CNPJ', CNPJ_RE, { label: 'Brazilian CNPJ', validator: cnpjValid }),
  regexScanner('card', 'CARD', CARD_RE, { label: 'Credit card number', validator: luhnValid }),
  // keyword token scanner uses 'd' flag implicitly via lookbehind; we add d
  // for index precision.
  tokenScanner('token', 'TOKEN', TOKEN_RE, { label: 'Bearer/token= keyword value' }),
  // opt-in categories
  regexScanner('ip', 'IP', IPV4_RE, { label: 'IPv4 address', optIn: true, validator: ipv4Valid }),
  regexScanner('mac', 'MAC', MAC_RE, { label: 'MAC address', optIn: true }),
  regexScanner('cep', 'CEP', CEP_RE, { label: 'Brazilian CEP', optIn: true, validator: cepValid }),
  regexScanner('pis', 'PIS', PIS_RE, { label: 'Brazilian PIS/NIS', optIn: true, validator: pisValid }),
  regexScanner('ssn', 'SSN', SSN_RE, { label: 'US SSN', optIn: true, validator: ssnValid }),
];

/** Keyword-bearer scanner that uses the 'd' flag for exact group indices. */
function tokenScanner(
  category: RedactCategory,
  token: string,
  re: RegExp,
  opts: { label: string; optIn?: boolean },
): Scanner {
  return {
    category,
    token,
    label: opts.label,
    optIn: opts.optIn,
    scan(text: string): Match[] {
      const src = re.source;
      const flags = (re.flags.includes('d') ? re.flags : re.flags + 'd').replace(/g?/, 'g');
      const g = new RegExp(src, flags);
      const out: Match[] = [];
      for (const m of text.matchAll(g)) {
        if (m.index === undefined) continue;
        const indices = (m as any).indices;
        if (!indices || !indices[1]) continue;
        const [s, e] = indices[1] as [number, number];
        out.push({ category, start: s, end: e, value: m[1] as string });
      }
      return out;
    },
  };
}

// ---------------------------------------------------------------------------
// Category sets
// ---------------------------------------------------------------------------

export const DEFAULT_CATEGORIES: readonly RedactCategory[] = [
  'email',
  'phone',
  'cpf',
  'cnpj',
  'apikey',
  'card',
  'dburl',
  'jwt',
  'privatekey',
  'aws',
  'token',
];

export const OPT_IN_CATEGORIES: readonly RedactCategory[] = [
  'ip',
  'mac',
  'cep',
  'pis',
  'ssn',
];

export const ALL_CATEGORIES: readonly RedactCategory[] = [
  ...DEFAULT_CATEGORIES,
  ...OPT_IN_CATEGORIES,
];

export function scannersFor(categories: readonly RedactCategory[]): Scanner[] {
  const set = new Set(categories);
  return SCANNERS.filter((s) => set.has(s.category));
}
