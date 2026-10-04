// Solana transaction wire format (legacy and v0) parser and PDA/ATA derivation, so the library
// needs no @solana/web3.js at runtime.
// Format: https://solana.com/docs/core/transactions
import { base58 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";

export const PROGRAMS = {
  TOKEN: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  TOKEN_2022: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
  COMPUTE_BUDGET: "ComputeBudget111111111111111111111111111111",
  MEMO: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
  MEMO_V1: "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
  LIGHTHOUSE: "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95",
  SYSTEM: "11111111111111111111111111111111",
  ATA: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
};

export const MAX_CU_PRICE_MICROLAMPORTS = 5_000_000n;

export interface ParsedInstruction {
  programIdIndex: number;
  accounts: number[];
  data: Uint8Array;
}

export interface ParsedTx {
  signatures: Uint8Array[];
  version: "legacy" | number;
  numRequiredSignatures: number;
  numReadonlySigned: number;
  numReadonlyUnsigned: number;
  accountKeys: string[];
  recentBlockhash: string;
  instructions: ParsedInstruction[];
  lookups: { account: string; writable: number[]; readonly: number[] }[];
  messageBytes: Uint8Array;
}

export class Reader {
  o = 0;
  constructor(public b: Uint8Array) {}
  u8(): number {
    if (this.o >= this.b.length) throw new Error("unexpected end of transaction bytes");
    return this.b[this.o++];
  }
  bytes(n: number): Uint8Array {
    if (this.o + n > this.b.length) throw new Error("unexpected end of transaction bytes");
    const out = this.b.slice(this.o, this.o + n);
    this.o += n;
    return out;
  }
  /** Solana compact-u16 (shortvec). */
  shortvec(): number {
    let len = 0;
    for (let i = 0; i < 3; i++) {
      const b = this.u8();
      // compact-u16 caps at 0xffff: the third byte may only carry 2 bits.
      if (i === 2 && b > 0x03) throw new Error("bad compact-u16");
      len |= (b & 0x7f) << (7 * i);
      if (!(b & 0x80)) return len;
    }
    throw new Error("bad compact-u16");
  }
}

/** Parse a serialized (possibly partially-signed) legacy or v0 transaction. */
export function parseTransaction(bytes: Uint8Array): ParsedTx {
  const r = new Reader(bytes);
  const nsig = r.shortvec();
  if (nsig > 64) throw new Error("implausible signature count");
  const signatures: Uint8Array[] = [];
  for (let i = 0; i < nsig; i++) signatures.push(r.bytes(64));
  const msgStart = r.o;
  let version: ParsedTx["version"] = "legacy";
  let first = r.u8();
  if (first & 0x80) {
    version = first & 0x7f;
    if (version !== 0) throw new Error(`unsupported transaction version ${version}`);
    first = r.u8();
  }
  const numRequiredSignatures = first;
  const numReadonlySigned = r.u8();
  const numReadonlyUnsigned = r.u8();
  const nkeys = r.shortvec();
  const accountKeys: string[] = [];
  for (let i = 0; i < nkeys; i++) accountKeys.push(base58.encode(r.bytes(32)));
  const recentBlockhash = base58.encode(r.bytes(32));
  const nix = r.shortvec();
  const instructions: ParsedInstruction[] = [];
  for (let i = 0; i < nix; i++) {
    const programIdIndex = r.u8();
    const na = r.shortvec();
    const accounts: number[] = [];
    for (let j = 0; j < na; j++) accounts.push(r.u8());
    const dl = r.shortvec();
    instructions.push({ programIdIndex, accounts, data: r.bytes(dl) });
  }
  const lookups: ParsedTx["lookups"] = [];
  if (version === 0) {
    const nl = r.shortvec();
    for (let i = 0; i < nl; i++) {
      const account = base58.encode(r.bytes(32));
      const w = r.shortvec();
      const writable = [...r.bytes(w)];
      const ro = r.shortvec();
      const readonly = [...r.bytes(ro)];
      lookups.push({ account, writable, readonly });
    }
  }
  if (r.o !== bytes.length) throw new Error(`${bytes.length - r.o} trailing bytes after the message`);
  if (numRequiredSignatures !== nsig) throw new Error(`header wants ${numRequiredSignatures} signatures but ${nsig} slots are present`);
  return {
    signatures,
    version,
    numRequiredSignatures,
    numReadonlySigned,
    numReadonlyUnsigned,
    accountKeys,
    recentBlockhash,
    instructions,
    lookups,
    messageBytes: bytes.slice(msgStart),
  };
}

/** Quick structural sniff so the detector doesn't treat random bytes as a tx. */
export function looksLikeTransaction(bytes: Uint8Array): boolean {
  try {
    const tx = parseTransaction(bytes);
    return tx.accountKeys.length > 0 && tx.instructions.every((ix) => ix.programIdIndex < tx.accountKeys.length);
  } catch {
    return false;
  }
}

/** Little-endian u32 at `o`. Throws instead of reading past the end (callers check lengths first). */
export function u32(d: Uint8Array, o: number): number {
  if (o < 0 || o + 4 > d.length) throw new Error(`u32 read at ${o} past the end of ${d.length} bytes`);
  return (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16)) + d[o + 3] * 0x1000000;
}

/** Little-endian u64 at `o`. Throws instead of reading past the end. */
export function u64(d: Uint8Array, o: number): bigint {
  if (o < 0 || o + 8 > d.length) throw new Error(`u64 read at ${o} past the end of ${d.length} bytes`);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(d[o + i]);
  return v;
}

export function isOnCurve(bytes: Uint8Array): boolean {
  try {
    ed25519.Point.fromBytes(bytes);
    return true;
  } catch {
    return false;
  }
}

export const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

/** findProgramAddress. */
export function findPda(seeds: Uint8Array[], programId: string): string | undefined {
  const pid = base58.decode(programId);
  for (let bump = 255; bump >= 0; bump--) {
    const parts = [...seeds, new Uint8Array([bump]), pid, PDA_MARKER];
    const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) {
      buf.set(p, o);
      o += p.length;
    }
    const h = sha256(buf);
    if (!isOnCurve(h)) return base58.encode(h);
  }
  return undefined;
}

/** The associated token account of `owner` for `mint`. */
export function associatedTokenAddress(owner: string, mint: string, tokenProgram = PROGRAMS.TOKEN): string | undefined {
  try {
    return findPda([base58.decode(owner), base58.decode(tokenProgram), base58.decode(mint)], PROGRAMS.ATA);
  } catch {
    return undefined;
  }
}
