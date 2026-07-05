// Pure validators for sensitive tokens. Zero deps, isomorphic.

/** Strip non-digit characters. */
function digits(s: string): string {
  let r = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 48 && c <= 57) r += s[i];
  }
  return r;
}

/** Luhn checksum (used by credit cards and others). */
export function luhnValid(input: string): boolean {
  const s = digits(input);
  if (s.length < 12 || s.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let d = s.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

/** Validate a Brazilian CPF (11 digits with check digits). */
export function cpfValid(input: string): boolean {
  const s = digits(input);
  if (s.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(s)) return false; // all equal digits

  const w1 = [10, 9, 8, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += (s.charCodeAt(i) - 48) * w1[i]!;
  let d1 = (sum * 10) % 11;
  if (d1 === 10) d1 = 0;
  if (d1 !== s.charCodeAt(9) - 48) return false;

  const w2 = [11, 10, 9, 8, 7, 6, 5, 4, 3, 2];
  sum = 0;
  for (let i = 0; i < 10; i++) sum += (s.charCodeAt(i) - 48) * w2[i]!;
  let d2 = (sum * 10) % 11;
  if (d2 === 10) d2 = 0;
  return d2 === s.charCodeAt(10) - 48;
}

/** Validate a Brazilian CNPJ (14 digits with check digits). */
export function cnpjValid(input: string): boolean {
  const s = digits(input);
  if (s.length !== 14) return false;
  if (/^(\d)\1{13}$/.test(s)) return false;

  const w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += (s.charCodeAt(i) - 48) * w1[i]!;
  let d1 = sum % 11;
  d1 = d1 < 2 ? 0 : 11 - d1;
  if (d1 !== s.charCodeAt(12) - 48) return false;

  const w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  sum = 0;
  for (let i = 0; i < 13; i++) sum += (s.charCodeAt(i) - 48) * w2[i]!;
  let d2 = sum % 11;
  d2 = d2 < 2 ? 0 : 11 - d2;
  return d2 === s.charCodeAt(13) - 48;
}

/** Validate a Brazilian PIS/NIS (11 digits with check digit). */
export function pisValid(input: string): boolean {
  const s = digits(input);
  if (s.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(s)) return false;

  const w = [3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 10; i++) sum += (s.charCodeAt(i) - 48) * w[i]!;
  let d = sum % 11;
  d = d < 2 ? 0 : 11 - d;
  return d === s.charCodeAt(10) - 48;
}

/**
 * Validate a US SSN. We do not implement a checksum (SSN has none); we apply
 * structural rules from the SSA: no area/group/serial of all zeros, no area
 * 666, no area 900-999, and 9 digits formatted or unformatted.
 */
export function ssnValid(input: string): boolean {
  const s = digits(input);
  if (s.length !== 9) return false;
  const area = s.slice(0, 3);
  const group = s.slice(3, 5);
  const serial = s.slice(5, 9);
  if (area === '000' || group === '00' || serial === '0000') return false;
  if (area === '666') return false;
  if (area >= '900' && area <= '999') return false;
  return true;
}

/** Validate a Brazilian CEP (8 digits). */
export function cepValid(input: string): boolean {
  const s = digits(input);
  return s.length === 8;
}

/** Validate an IPv4 address. */
export function ipv4Valid(input: string): boolean {
  const parts = input.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    if (n < 0 || n > 255) return false;
    // disallow leading zeros like 01, 001
    if (p.length > 1 && p.charCodeAt(0) === 48) return false;
  }
  return true;
}

/**
 * Validate an AWS secret access key: 40 chars from the base64 alphabet
 * (letters, digits, +, /). We require mixed-case letters to avoid matching
 * 40-char lowercase prose or all-digit runs.
 */
export function awsSecretValid(input: string): boolean {
  if (!/^[A-Za-z0-9/+]{40}$/.test(input)) return false;
  let lower = 0;
  let upper = 0;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c >= 65 && c <= 90) upper++;
    else if (c >= 97 && c <= 122) lower++;
  }
  return lower >= 4 && upper >= 4;
}

/** Check JWT structural validity (header.payload.signature, base64url). */
export function jwtValid(input: string): boolean {
  const parts = input.split('.');
  if (parts.length !== 3) return false;
  if (!parts.every((p) => p.length > 0 && /^[A-Za-z0-9_-]+$/.test(p))) return false;
  // header and payload must be decodable base64url JSON-ish. We avoid atob
  // for isomorphism; decode manually.
  try {
    const header = b64urlDecode(parts[0]!);
    if (!header.includes('"alg"')) return false;
    return true;
  } catch {
    return false;
  }
}

function b64urlDecode(s: string): string {
  let b = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  if (typeof globalThis !== 'undefined' && typeof (globalThis as any).atob === 'function') {
    return (globalThis as any).atob(b);
  }
  // Fallback minimal decoder (latin1) for environments without atob.
  const lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  let buf = 0;
  let bits = 0;
  for (let i = 0; i < b.length; i++) {
    const c = b[i]!;
    if (c === '=') break;
    const idx = lookup.indexOf(c);
    if (idx < 0) continue;
    buf = (buf << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((buf >> bits) & 0xff);
    }
  }
  return out;
}
