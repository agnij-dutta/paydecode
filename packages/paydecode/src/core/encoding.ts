// Input unwrapping (pasted headers, curl -H, quotes) and lenient base64/base64url/JSON helpers.
import { base64, base64url, base64nopad, base64urlnopad, hex } from "@scure/base";

export const HEADER_PREFIX =
  /^\s*(?:-H\s*|--header\s*)?(['"]?)\s*(x-payment-response|x-payment|payment-required|payment-signature|payment-response|payment-receipt|payment-authorization|www-authenticate|authorization|signature-input|signature|extension-responses)\s*:\s*/i;

export interface Unwrapped {
  /** Header name the user pasted along with the value, lowercased, if any. */
  header?: string;
  text: string;
}

/** Strip a pasted `Header-Name: value` (or curl `-H '...'`) wrapper and quotes. */
export function unwrapHeader(input: string): Unwrapped {
  let text = input.trim();
  let header: string | undefined;
  const m = text.match(HEADER_PREFIX);
  if (m) {
    header = m[2].toLowerCase();
    text = text.slice(m[0].length).trim();
    const q = m[1];
    if (q && text.endsWith(q)) text = text.slice(0, -1);
    else if (q && text.includes(q)) text = text.slice(0, text.lastIndexOf(q));
  } else if (text.length > 1 && (text[0] === "'" || text[0] === '"') && text.endsWith(text[0])) {
    text = text.slice(1, -1);
  }
  return { header, text: text.trim() };
}

export const B64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;

/** Decode base64 or base64url, with or without padding. Returns null if it isn't. */
export function decodeBase64(s: string): Uint8Array | null {
  const t = s.replace(/\s+/g, "");
  if (t.length < 4 || !B64_RE.test(t)) return null;
  for (const codec of [base64, base64nopad, base64url, base64urlnopad]) {
    try {
      return codec.decode(t);
    } catch {
      /* try next */
    }
  }
  return null;
}

export function utf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

/**
 * Nesting limit for untrusted JSON. Real payment artifacts nest fewer than 10 levels; the
 * decoders walk values recursively, so a 100k-deep array would otherwise overflow the stack.
 */
export const MAX_JSON_DEPTH = 64;

/** True if `s` nests objects/arrays deeper than `max` (string contents are skipped). Linear, no recursion. */
export function jsonTooDeep(s: string, max = MAX_JSON_DEPTH): boolean {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (inString) {
      if (c === 92)
        i++; // backslash: skip the escaped char
      else if (c === 34) inString = false;
    } else if (c === 34) inString = true;
    else if (c === 123 || c === 91) {
      if (++depth > max) return true;
    } else if (c === 125 || c === 93) depth--;
  }
  return false;
}

/** Define an own data property, so an untrusted "__proto__" key can't swap the object's prototype. */
export function setOwn(o: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(o, key, { value, enumerable: true, writable: true, configurable: true });
}

export function tryJson(s: string): unknown {
  const t = s.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return undefined;
  if (jsonTooDeep(t)) return undefined;
  try {
    return JSON.parse(t);
  } catch {
    return undefined;
  }
}

/** base64 -> JSON, if the bytes are UTF-8 JSON. */
export function base64Json(s: string): unknown {
  const bytes = decodeBase64(s);
  if (!bytes) return undefined;
  return tryJson(utf8(bytes));
}

export function hexToBytes(h: string): Uint8Array {
  const t = h.startsWith("0x") ? h.slice(2) : h;
  return hex.decode(t.length % 2 ? "0" + t : t);
}

export function bytesToHex(b: Uint8Array): string {
  return "0x" + hex.encode(b);
}

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Encode bytes as unpadded base64url (JWT style). */
export function b64url(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

/** Decode a base64url segment (padding optional). Returns null on failure. */
export function fromB64url(s: string): Uint8Array | null {
  const t = s.replace(/=+$/, "");
  if (!/^[A-Za-z0-9_-]*$/.test(t)) return null;
  try {
    return base64urlnopad.decode(t);
  } catch {
    return null;
  }
}

/** Parse a JSON string, returning undefined instead of throwing. Accepts any JSON value. */
export function parseJsonLoose(s: string): unknown {
  if (jsonTooDeep(s)) return undefined;
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}
