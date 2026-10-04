// SD-JWT (RFC 9901) parsing, disclosure resolution, ES256 verification and
// delegation-chain (`~~`) splitting, as used by AP2 v0.2 mandates.
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { p256 } from "@noble/curves/nist.js";
import { b64url, fromB64url, isRecord, parseJsonLoose, utf8 } from "../core/encoding.js";
import { asText } from "../core/format.js";

type Obj = Record<string, unknown>;

export interface Disclosure {
  raw: string;
  digest: string;
  salt: string;
  /** Present for object-property disclosures. */
  name?: string;
  value: unknown;
  used: boolean;
}

export interface Jwt {
  raw: string;
  header: Obj;
  payload: Obj;
  signature: Uint8Array;
  signingInput: string;
}

export interface SdToken {
  /** As pasted, for display. */
  raw: string;
  jwt: Jwt;
  disclosures: Disclosure[];
  /** Canonical `issuer_jwt~d1~...~` form (what sd_hash covers). */
  sdJwt: string;
  /** Payload with disclosures resolved and `_sd` / `...` markers removed. */
  resolved: Obj;
  /** Digests that had no matching disclosure (selectively hidden claims). */
  undisclosed: number;
}

export function parseJwt(raw: string): Jwt | undefined {
  const parts = raw.trim().split(".");
  if (parts.length !== 3) return undefined;
  const h = fromB64url(parts[0]);
  const p = fromB64url(parts[1]);
  const s = fromB64url(parts[2]);
  if (!h || !p || !s) return undefined;
  const header = parseJsonLoose(utf8(h));
  const payload = parseJsonLoose(utf8(p));
  if (!isRecord(header) || !isRecord(payload)) return undefined;
  return { raw: raw.trim(), header, payload, signature: s, signingInput: `${parts[0]}.${parts[1]}` };
}

export const enc = new TextEncoder();

/**
 * base64url(hash(ascii(s))) with the SD-JWT `_sd_alg` (sha-256 default). Used both for disclosure
 * digests (RFC 9901 section 4.2.3) and for KB-JWT `sd_hash`, which covers the previous token
 * including its trailing "~".
 */
export function sdHash(s: string, alg: unknown = "sha-256"): string {
  const a = asText(alg, "sha-256").toLowerCase();
  const fn = a === "sha-384" ? sha384 : a === "sha-512" ? sha512 : sha256;
  return b64url(fn(enc.encode(s)));
}

export function resolve(v: unknown, byDigest: Map<string, Disclosure>, counter: { undisclosed: number }): unknown {
  if (Array.isArray(v)) {
    const out: unknown[] = [];
    for (const el of v) {
      if (isRecord(el) && Object.keys(el).length === 1 && typeof el["..."] === "string") {
        const d = byDigest.get(el["..."]);
        if (d && d.name === undefined) {
          d.used = true;
          out.push(resolve(d.value, byDigest, counter));
        } else counter.undisclosed++;
      } else out.push(resolve(el, byDigest, counter));
    }
    return out;
  }
  if (isRecord(v)) {
    const out: Obj = {};
    for (const [k, val] of Object.entries(v)) {
      if (k === "_sd" || k === "_sd_alg") continue;
      out[k] = resolve(val, byDigest, counter);
    }
    if (Array.isArray(v._sd)) {
      for (const dg of v._sd) {
        const d = byDigest.get(asText(dg));
        if (d && d.name !== undefined) {
          d.used = true;
          out[d.name] = resolve(d.value, byDigest, counter);
        } else counter.undisclosed++;
      }
    }
    return out;
  }
  return v;
}

/** Parse one SD-JWT (issuer JWT plus `~`-separated disclosures). */
export function parseSdToken(raw: string): SdToken | undefined {
  const parts = raw.trim().split("~");
  const jwt = parseJwt(parts[0]);
  if (!jwt) return undefined;
  const alg = jwt.payload._sd_alg ?? "sha-256";
  const discRaw = parts.slice(1).filter((p) => p.length);
  const disclosures: Disclosure[] = [];
  for (const d of discRaw) {
    const bytes = fromB64url(d);
    const arr = bytes ? parseJsonLoose(utf8(bytes)) : undefined;
    if (!Array.isArray(arr) || (arr.length !== 2 && arr.length !== 3)) continue;
    disclosures.push({
      raw: d,
      digest: sdHash(d, alg),
      salt: asText(arr[0]),
      name: arr.length === 3 ? asText(arr[1]) : undefined,
      value: arr.length === 3 ? arr[2] : arr[1],
      used: false,
    });
  }
  const byDigest = new Map(disclosures.map((d) => [d.digest, d]));
  const counter = { undisclosed: 0 };
  const resolved = resolve(jwt.payload, byDigest, counter) as Obj;
  const sdJwt = jwt.raw + "~" + discRaw.join("~") + (discRaw.length ? "~" : "");
  return { raw, jwt, disclosures, sdJwt, resolved, undisclosed: counter.undisclosed };
}

/** Split an AP2 delegation chain on `~~` and parse each hop. */
export function parseChain(input: string): SdToken[] | undefined {
  const hops = input.trim().split("~~");
  const out: SdToken[] = [];
  for (const h of hops) {
    const t = parseSdToken(h);
    if (!t) return undefined;
    out.push(t);
  }
  return out;
}

/** Verify an ES256 JWS over its signing input with a P-256 JWK. */
export function verifyEs256(jwt: Jwt, jwk: unknown): boolean {
  if (!isRecord(jwk) || jwk.kty !== "EC" || jwk.crv !== "P-256") return false;
  const x = fromB64url(asText(jwk.x, ""));
  const y = fromB64url(asText(jwk.y, ""));
  if (!x || !y || x.length !== 32 || y.length !== 32 || jwt.signature.length !== 64) return false;
  const pub = new Uint8Array(65);
  pub[0] = 4;
  pub.set(x, 1);
  pub.set(y, 33);
  try {
    return p256.verify(jwt.signature, enc.encode(jwt.signingInput), pub, { lowS: false });
  } catch {
    return false;
  }
}

/** Find a `cnf.jwk` inside a resolved token: delegate_payload items first, then top level. */
export function findCnfJwk(t: SdToken): Obj | undefined {
  const dp = t.resolved.delegate_payload;
  if (Array.isArray(dp)) {
    for (const item of dp) if (isRecord(item) && isRecord(item.cnf) && isRecord(item.cnf.jwk)) return item.cnf.jwk;
  }
  if (isRecord(t.resolved.cnf) && isRecord(t.resolved.cnf.jwk)) return t.resolved.cnf.jwk;
  return undefined;
}

export const looksLikeJwt = (s: string) => /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(s.trim());
export const looksLikeSdJwt = (s: string) => /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*~/.test(s.trim());
