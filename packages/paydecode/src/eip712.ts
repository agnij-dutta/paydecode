// Minimal EIP-712 hashing + signer recovery. Supports flat structs (EIP-3009
// TransferWithAuthorization) and nested structs / arrays (Permit2
// PermitWitnessTransferFrom). Isomorphic: no node: imports.
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hexToBytes, bytesToHex } from "./encoding.js";

export interface TypedField {
  name: string;
  type: string;
}

export type TypeMap = Record<string, TypedField[]>;

export interface Domain {
  name?: string;
  version?: string;
  chainId?: number | bigint;
  verifyingContract?: string;
  salt?: string;
}

const enc = new TextEncoder();

function word(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = BigInt.asUintN(256, n);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function toBigInt(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "boolean") return value ? 1n : 0n;
  return BigInt(String(value));
}

/** Collect the struct types `primary` depends on (including itself). */
function dependencies(primary: string, types: TypeMap, found: Set<string> = new Set()): Set<string> {
  const base = primary.replace(/\[\d*\]$/, "");
  if (found.has(base) || !types[base]) return found;
  found.add(base);
  for (const f of types[base]) dependencies(f.type.replace(/(\[\d*\])+$/, ""), types, found);
  return found;
}

/** EIP-712 encodeType: primary type first, then referenced structs sorted by name. */
export function encodeType(primary: string, types: TypeMap): string {
  const deps = [...dependencies(primary, types)].filter((t) => t !== primary).sort();
  return [primary, ...deps].map((t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(",")})`).join("");
}

export function typeHash(primary: string, types: TypeMap): Uint8Array {
  return keccak_256(enc.encode(encodeType(primary, types)));
}

function encodeField(type: string, value: unknown, types: TypeMap): Uint8Array {
  const arr = type.match(/^(.*)\[(\d*)\]$/);
  if (arr) {
    const inner = arr[1];
    const items = Array.isArray(value) ? value : [];
    return keccak_256(concatBytes(items.map((v) => encodeField(inner, v, types))));
  }
  if (types[type]) return hashStructTyped(type, types, (value ?? {}) as Record<string, unknown>);
  if (type === "string") return keccak_256(enc.encode(String(value)));
  if (type === "bytes") return keccak_256(hexToBytes(String(value)));
  if (type === "address") return word(toBigInt(value));
  if (type === "bool") return word(value === true || value === "true" ? 1n : 0n);
  if (/^u?int\d*$/.test(type)) return word(toBigInt(value));
  if (/^bytes\d+$/.test(type)) {
    const b = hexToBytes(String(value));
    const out = new Uint8Array(32);
    out.set(b.slice(0, 32));
    return out;
  }
  throw new Error(`unsupported EIP-712 type ${type}`);
}

export function hashStructTyped(primary: string, types: TypeMap, message: Record<string, unknown>): Uint8Array {
  const fields = types[primary];
  if (!fields) throw new Error(`unknown EIP-712 type ${primary}`);
  return keccak_256(concatBytes([typeHash(primary, types), ...fields.map((f) => encodeField(f.type, message[f.name], types))]));
}

/** Flat-struct convenience kept for backwards compatibility. */
export function hashStruct(primaryType: string, fields: TypedField[], message: Record<string, unknown>): Uint8Array {
  return hashStructTyped(primaryType, { [primaryType]: fields }, message);
}

export function domainFields(d: Domain): TypedField[] {
  const f: TypedField[] = [];
  if (d.name !== undefined) f.push({ name: "name", type: "string" });
  if (d.version !== undefined) f.push({ name: "version", type: "string" });
  if (d.chainId !== undefined) f.push({ name: "chainId", type: "uint256" });
  if (d.verifyingContract !== undefined) f.push({ name: "verifyingContract", type: "address" });
  if (d.salt !== undefined) f.push({ name: "salt", type: "bytes32" });
  return f;
}

export function domainSeparator(domain: Domain): Uint8Array {
  return hashStruct("EIP712Domain", domainFields(domain), domain as Record<string, unknown>);
}

/** Digest for a full typed-data object with (possibly nested) struct types. */
export function typedDataHash(
  domain: Domain,
  types: TypeMap,
  primaryType: string,
  message: Record<string, unknown>,
): Uint8Array {
  const ds = domainSeparator(domain);
  const ms = hashStructTyped(primaryType, types, message);
  return keccak_256(concatBytes([new Uint8Array([0x19, 0x01]), ds, ms]));
}

/** Flat-struct digest (original API). */
export function typedDataDigest(
  domain: Domain,
  primaryType: string,
  fields: TypedField[],
  message: Record<string, unknown>,
): Uint8Array {
  return typedDataHash(domain, { [primaryType]: fields }, primaryType, message);
}

export function checksumAddress(addr: string): string {
  const a = addr.toLowerCase().replace(/^0x/, "");
  const h = keccak_256(enc.encode(a));
  let out = "0x";
  for (let i = 0; i < 40; i++) {
    const nibble = (h[i >> 1] >> (i % 2 ? 0 : 4)) & 0xf;
    out += nibble >= 8 ? a[i].toUpperCase() : a[i];
  }
  return out;
}

/**
 * Recover the signing address from a 65-byte (r,s,v) signature over a digest.
 * Accepts v in {0,1,27,28}. Also accepts 64-byte EIP-2098 compact signatures.
 */
export function recoverAddress(digest: Uint8Array, signature: string): string | null {
  try {
    const sig = hexToBytes(signature.startsWith("0x") ? signature : "0x" + signature);
    let rs: Uint8Array;
    let v: number;
    if (sig.length === 65) {
      rs = sig.slice(0, 64);
      v = sig[64];
      if (v >= 27) v -= 27;
    } else if (sig.length === 64) {
      // EIP-2098: yParityAndS
      rs = sig.slice();
      v = rs[32] >> 7;
      rs[32] &= 0x7f;
    } else return null;
    if (v > 1) return null;
    const s = secp256k1.Signature.fromBytes(rs, "compact").addRecoveryBit(v);
    const pub = s.recoverPublicKey(digest).toBytes(false);
    return checksumAddress(bytesToHex(keccak_256(pub.slice(1)).slice(-20)));
  } catch {
    return null;
  }
}

export const isEvmAddress = (s: unknown): s is string => typeof s === "string" && /^0x[0-9a-fA-F]{40}$/.test(s);

export const sameAddress = (a: unknown, b: unknown): boolean =>
  typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();

export function keccakUtf8(s: string): string {
  return bytesToHex(keccak_256(enc.encode(s)));
}
