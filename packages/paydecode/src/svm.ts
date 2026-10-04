// Solana (SVM) exact payments: a tiny parser for the versioned transaction
// wire format plus plain-English instruction decoding. No @solana/web3.js at runtime.
import { base58 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import type { Field, Flag, Section } from "./types.js";
import { field, flag, formatUnits, short, section, plural } from "./format.js";
import { findSplToken, networkInfo } from "./networks.js";
import type { Analysis, PaymentContext } from "./evm.js";

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

class Reader {
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

const u32 = (d: Uint8Array, o: number) => (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16)) + d[o + 3] * 0x1000000;
function u64(d: Uint8Array, o: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(d[o + i] ?? 0);
  return v;
}

function isOnCurve(bytes: Uint8Array): boolean {
  try {
    ed25519.Point.fromBytes(bytes);
    return true;
  } catch {
    return false;
  }
}

const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

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

interface DecodedIx {
  program: string;
  programName: string;
  text: string;
  known: boolean;
}

export interface SvmTransfer {
  kind: "TransferChecked" | "Transfer";
  amount: bigint;
  decimals?: number;
  source: string;
  mint?: string;
  destination: string;
  authority: string;
  tokenProgram: string;
}

const isZero = (b: Uint8Array) => b.every((x) => x === 0);

/** Decode + check an exact/SVM payment transaction. */
export function analyzeSvmTransaction(b64tx: string, txBytes: Uint8Array, ctx: PaymentContext, now: number): Analysis {
  void now;
  const tx = parseTransaction(txBytes);
  const key = (i: number) => tx.accountKeys[i] ?? `(lookup-table account #${i - tx.accountKeys.length})`;
  const flags: Flag[] = [];
  const ixs: DecodedIx[] = [];
  const transfers: SvmTransfer[] = [];
  let cuLimit: number | undefined;
  let cuPrice: bigint | undefined;
  const memos: string[] = [];
  const feePayer = tx.accountKeys[0];

  for (const ix of tx.instructions) {
    const program = key(ix.programIdIndex);
    const d = ix.data;
    const acc = (n: number) => key(ix.accounts[n]);
    let out: DecodedIx = { program, programName: "Unknown program", text: `Calls ${short(program)} with ${d.length} bytes of data`, known: false };
    if (program === PROGRAMS.COMPUTE_BUDGET) {
      const name = "Compute Budget";
      if (d[0] === 2) {
        cuLimit = u32(d, 1);
        out = { program, programName: name, text: `Set compute unit limit to ${cuLimit.toLocaleString("en-US")}`, known: true };
      } else if (d[0] === 3) {
        cuPrice = u64(d, 1);
        out = { program, programName: name, text: `Set priority fee to ${cuPrice.toLocaleString("en-US")} microlamports per compute unit`, known: true };
      } else if (d[0] === 1) out = { program, programName: name, text: `Request heap frame of ${u32(d, 1)} bytes`, known: true };
      else if (d[0] === 4) out = { program, programName: name, text: `Limit loaded account data to ${u32(d, 1)} bytes`, known: true };
      else out = { program, programName: name, text: `Compute budget instruction ${d[0]}`, known: true };
    } else if (program === PROGRAMS.TOKEN || program === PROGRAMS.TOKEN_2022) {
      const name = program === PROGRAMS.TOKEN ? "SPL Token" : "Token-2022";
      const tag = d[0];
      if (tag === 12 && d.length >= 10) {
        const t: SvmTransfer = { kind: "TransferChecked", amount: u64(d, 1), decimals: d[9], source: acc(0), mint: acc(1), destination: acc(2), authority: acc(3), tokenProgram: program };
        transfers.push(t);
        const tok = findSplToken(t.mint);
        out = {
          program,
          programName: name,
          text: `TransferChecked ${formatUnits(t.amount, t.decimals!)} ${tok?.symbol ?? `of mint ${short(t.mint)}`} from token account ${short(t.source)} to token account ${short(t.destination)}, authorized by ${short(t.authority)}`,
          known: true,
        };
      } else if (tag === 3 && d.length >= 9) {
        const t: SvmTransfer = { kind: "Transfer", amount: u64(d, 1), source: acc(0), destination: acc(1), authority: acc(2), tokenProgram: program };
        transfers.push(t);
        out = { program, programName: name, text: `Transfer ${t.amount} raw units (unchecked, no mint or decimals) from ${short(t.source)} to ${short(t.destination)}`, known: true };
      } else if (tag === 4 || tag === 13) {
        out = { program, programName: name, text: `Approve delegate ${short(acc(tag === 4 ? 1 : 2))} to spend ${u64(d, 1)} raw units from ${short(acc(0))}`, known: true };
        flags.push(flag("danger", "SVM_APPROVE", `Instruction approves ${short(acc(tag === 4 ? 1 : 2))} as a delegate over the payer's token account. An x402 payment never needs this: the delegate could drain the account later.`));
      } else if (tag === 6) {
        out = { program, programName: name, text: `SetAuthority on ${short(acc(0))}`, known: true };
        flags.push(flag("danger", "SVM_SET_AUTHORITY", `Instruction changes the authority of ${short(acc(0))}. Signing this hands over control of the account.`));
      } else if (tag === 9) {
        out = { program, programName: name, text: `Close token account ${short(acc(0))}, sending its rent to ${short(acc(1))}`, known: true };
        flags.push(flag("warn", "SVM_CLOSE_ACCOUNT", `Instruction closes token account ${short(acc(0))}.`));
      } else out = { program, programName: name, text: `Token instruction #${tag}`, known: true };
    } else if (program === PROGRAMS.MEMO || program === PROGRAMS.MEMO_V1) {
      const text = new TextDecoder().decode(d);
      memos.push(text);
      out = { program, programName: "Memo", text: `Memo "${text.length > 80 ? text.slice(0, 80) + "…" : text}"`, known: true };
    } else if (program === PROGRAMS.LIGHTHOUSE) {
      out = { program, programName: "Lighthouse", text: "Lighthouse assertion (wallet guard injected by Phantom/Solflare)", known: true };
    } else if (program === PROGRAMS.SYSTEM) {
      if (u32(d, 0) === 2) {
        const lamports = u64(d, 4);
        out = { program, programName: "System", text: `Transfer ${formatUnits(lamports, 9)} SOL from ${short(acc(0))} to ${short(acc(1))}`, known: true };
        flags.push(flag(acc(0) === feePayer ? "danger" : "warn", "SVM_SOL_TRANSFER", `Also moves ${formatUnits(lamports, 9)} SOL from ${short(acc(0))}${acc(0) === feePayer ? " (the fee payer!)" : ""} to ${short(acc(1))}. x402 exact payments only transfer the token.`));
      } else out = { program, programName: "System", text: `System instruction #${u32(d, 0)}`, known: true };
    } else if (program === PROGRAMS.ATA) {
      out = { program, programName: "Associated Token Account", text: `Create${d[0] === 1 ? " (idempotent)" : ""} associated token account ${short(acc(1))} for owner ${short(acc(2))}, rent paid by ${short(acc(0))}`, known: true };
      flags.push(flag(acc(0) === feePayer ? "warn" : "info", "SVM_CREATE_ATA", `Creates a token account for ${short(acc(2))}${acc(0) === feePayer ? ", with rent paid by the fee payer (facilitator). Strict facilitators reject this" : ""}.`));
    }
    if (!out.known) {
      flags.push(flag("warn", "SVM_UNKNOWN_PROGRAM", `Calls unrecognized program ${short(program)}. x402 facilitators only accept compute budget, token transfer, memo and Lighthouse instructions; anything else is rejected or should be audited.`));
    }
    ixs.push(out);
  }

  // Signatures
  const sigFields: Field[] = [];
  let clientSigOk = 0;
  let clientSigBad = 0;
  let clientSigMissing = 0;
  for (let i = 0; i < tx.numRequiredSignatures; i++) {
    const signer = tx.accountKeys[i];
    const sig = tx.signatures[i];
    const role = i === 0 ? "fee payer" : "signer";
    if (!sig || isZero(sig)) {
      sigFields.push(field(`Signature ${i + 1} (${role})`, "not signed yet", "text", short(signer)));
      if (i > 0) {
        clientSigMissing++;
        flags.push(flag("danger", "SVM_SIGNER_MISSING", `Required signer ${short(signer)} has not signed. The facilitator can't settle a transaction missing the payer's signature.`));
      }
      continue;
    }
    let ok = false;
    try {
      ok = ed25519.verify(sig, tx.messageBytes, base58.decode(signer));
    } catch {
      ok = false;
    }
    sigFields.push(field(`Signature ${i + 1} (${role})`, base58.encode(sig), "code", `${short(signer)}: ${ok ? "valid" : "INVALID"}`));
    if (i === 0) continue;
    if (ok) clientSigOk++;
    else {
      clientSigBad++;
      flags.push(flag("danger", "SIG_INVALID", `Signature by ${short(signer)} does not verify over this message. The transaction was modified after signing.`));
    }
  }
  const feeSig = tx.signatures[0];
  if (!feeSig || isZero(feeSig)) {
    flags.push(flag("info", "SVM_FEE_PAYER_UNSIGNED", `Fee payer ${short(feePayer)} hasn't signed yet. That's expected: in x402 the facilitator co-signs as fee payer at settlement.`));
  } else {
    flags.push(flag("info", "SVM_FEE_PAYER_SIGNED", `Fee payer ${short(feePayer)} already signed, so this is a fully signed transaction rather than an x402 client payload.`));
  }
  if (clientSigOk && !clientSigBad) flags.push(flag("ok", "SIG_VALID", `Payer signature${clientSigOk > 1 ? "s" : ""} verified (ed25519 over the message).`));
  const expectedFeePayer = typeof ctx.extra?.feePayer === "string" ? ctx.extra.feePayer : undefined;
  if (expectedFeePayer && expectedFeePayer !== feePayer) {
    flags.push(flag("danger", "SVM_FEE_PAYER_MISMATCH", `Fee payer is ${short(feePayer)} but the requirements name ${short(expectedFeePayer)} (extra.feePayer). The facilitator can't co-sign it.`));
  }

  // Compute budget
  if (cuPrice !== undefined && cuPrice > MAX_CU_PRICE_MICROLAMPORTS) {
    const fee = cuLimit !== undefined ? (cuPrice * BigInt(cuLimit)) / 1_000_000n : undefined;
    flags.push(
      flag(
        "danger",
        "SVM_CU_PRICE_HIGH",
        `Priority fee is ${cuPrice.toLocaleString("en-US")} microlamports per CU, above x402's cap of 5,000,000. Facilitators reject it because the fee payer (not the client) would eat ${fee !== undefined ? `${formatUnits(fee, 9)} SOL in priority fees` : "the priority fee"}.`,
      ),
    );
  }
  if (cuPrice === undefined || cuLimit === undefined) {
    flags.push(flag("warn", "SVM_NO_COMPUTE_BUDGET", "Missing a compute unit limit or price instruction. x402 exact transactions are expected to set both."));
  }

  // Transfer checks
  const tr = transfers[0];
  if (!tr) flags.push(flag("danger", "SVM_NO_TRANSFER", "No token transfer instruction found. This transaction doesn't pay anything."));
  if (transfers.length > 1) flags.push(flag("warn", "SVM_MULTIPLE_TRANSFERS", `Contains ${transfers.length} token transfers; x402 exact expects exactly one.`));
  if (tr && tr.kind === "Transfer") flags.push(flag("warn", "SVM_UNCHECKED_TRANSFER", "Uses the unchecked Transfer instruction (no mint/decimals). x402 requires TransferChecked."));
  const tok = tr?.mint ? findSplToken(tr.mint) : undefined;
  const amt = tr ? (tr.decimals !== undefined ? `${formatUnits(tr.amount, tr.decimals)} ${tok?.symbol ?? `tokens of mint ${short(tr.mint)}`}` : `${tr.amount} raw units`) : "nothing";
  let destPhrase = tr ? `token account ${short(tr.destination)}` : "";
  if (tr) {
    if (tr.authority === feePayer) {
      flags.push(flag("danger", "SVM_FEE_PAYER_IS_AUTHORITY", `The fee payer ${short(feePayer)} is also the transfer authority, so the facilitator would be paying from its own funds. Facilitators must reject this.`));
    }
    const feePayerInIx = tx.instructions.some((ix) => key(ix.programIdIndex) !== PROGRAMS.ATA && ix.accounts.some((a) => tx.accountKeys[a] === feePayer));
    if (feePayerInIx && tr.authority !== feePayer) {
      flags.push(flag("warn", "SVM_FEE_PAYER_IN_INSTRUCTION", `Fee payer ${short(feePayer)} appears as an account in an instruction. x402 facilitators refuse to sign transactions that touch their own accounts.`));
    }
    if (ctx.asset && tr.mint && ctx.asset !== tr.mint) {
      flags.push(flag("danger", "SVM_MINT_MISMATCH", `Transfers mint ${short(tr.mint)} but the requirements ask for ${short(ctx.asset)}.`));
    }
    if (tok && tr.decimals !== undefined && tok.decimals !== tr.decimals) {
      flags.push(flag("danger", "SVM_DECIMALS_MISMATCH", `TransferChecked says ${tr.decimals} decimals but ${tok.symbol} has ${tok.decimals}; the token program will reject it.`));
    }
    if (!tok && tr.mint) flags.push(flag("warn", "UNKNOWN_ASSET", `Mint ${short(tr.mint)} isn't a token paydecode knows.`));
    if (ctx.amount !== undefined) {
      try {
        const req = BigInt(String(ctx.amount));
        const label = ctx.amountLabel ?? "the required amount";
        if (tr.amount > req) flags.push(flag("danger", "AMOUNT_OVERPAY", `Transfers ${tr.amount} raw units but ${label} is ${req}. The payer would overpay.`));
        else if (tr.amount < req) flags.push(flag("warn", "AMOUNT_UNDERPAY", `Transfers ${tr.amount} raw units but ${label} is ${req}; the server should reject it.`));
        else flags.push(flag("ok", "AMOUNT_MATCHES", `Amount matches ${label}.`));
      } catch {
        /* ignore */
      }
    }
    if (ctx.payTo && tr.mint) {
      const ata = associatedTokenAddress(ctx.payTo, tr.mint, tr.tokenProgram);
      if (ata === tr.destination) {
        flags.push(flag("ok", "PAYTO_MATCHES", `Destination is payTo ${short(ctx.payTo)}'s associated token account.`));
        destPhrase = `${short(ctx.payTo)} (its ${tok?.symbol ?? "token"} account)`;
      } else {
        flags.push(flag("danger", "PAYTO_MISMATCH", `Destination ${short(tr.destination)} is not payTo ${short(ctx.payTo)}'s associated token account (${short(ata)}). The money would go somewhere else.`));
      }
    }
  }
  if (memos.length) flags.push(flag("info", "SVM_MEMO", `Carries a memo: "${memos.join(" | ").slice(0, 120)}".`));

  const net = ctx.network ? networkInfo(ctx.network) : undefined;
  const netName = net?.name ?? tok?.network;
  const sigPhrase = clientSigBad
    ? "Payer signature INVALID."
    : clientSigMissing
      ? "Payer signature missing."
      : clientSigOk
        ? "Payer signature valid; fee payer signs at settlement."
        : "No payer signatures to check.";
  const summary = tr
    ? `Solana transaction that pays ${amt}${netName ? ` on ${netName}` : ""} from ${short(tr.authority)} to ${destPhrase}, with ${short(feePayer)} as fee payer. ${sigPhrase}`
    : `Solana transaction with ${plural(tx.instructions.length, "instruction")} and no token transfer. ${sigPhrase}`;

  const sections: Section[] = [
    section("Transaction", [
      field("Version", tx.version === "legacy" ? "legacy" : `v${tx.version}`),
      field("Fee payer", feePayer, "address", expectedFeePayer ? (expectedFeePayer === feePayer ? "matches extra.feePayer" : "does NOT match extra.feePayer") : undefined),
      field("Recent blockhash", tx.recentBlockhash, "hash", "blockhashes expire after about 60 to 90 seconds"),
      field("Required signatures", String(tx.numRequiredSignatures)),
      ...(cuLimit !== undefined ? [field("Compute unit limit", cuLimit.toLocaleString("en-US"))] : []),
      ...(cuPrice !== undefined ? [field("Compute unit price", `${cuPrice.toLocaleString("en-US")} microlamports`, "text", cuPrice > MAX_CU_PRICE_MICROLAMPORTS ? "above the 5,000,000 cap" : "within the 5,000,000 cap")] : []),
      ...(tx.lookups.length ? [field("Address lookup tables", tx.lookups.map((l) => l.account).join(", "), "code", "accounts loaded from tables can't be resolved offline")] : []),
    ]),
    section(
      "Instructions",
      ixs.map((x, i) => field(`${i + 1}. ${x.programName}`, x.text, "text", short(x.program))),
    ),
    ...(tr
      ? [
          section("Transfer", [
            field("Amount", amt, "amount", `raw ${tr.amount}`),
            ...(tr.mint ? [field("Mint", tr.mint, "address", tok ? `${tok.symbol} (${tok.network})` : "unknown mint")] : []),
            field("Source token account", tr.source, "address"),
            field("Destination token account", tr.destination, "address"),
            field("Authority (payer)", tr.authority, "address"),
          ]),
        ]
      : []),
    section("Signatures", sigFields),
    section("Encoded", [field("Transaction (base64)", b64tx, "code")]),
  ];
  return { sections, flags, summary, sigPhrase, payer: tr?.authority };
}
