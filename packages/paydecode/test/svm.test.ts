import { describe, it, expect } from "vitest";
import {
  Keypair,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
  TransactionInstruction,
  ComputeBudgetProgram,
  Transaction,
} from "@solana/web3.js";
import { parseTransaction, associatedTokenAddress } from "../src/index.js";
import { b64, codes, flagOf, dec } from "./helpers.js";

const TOKEN = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA_PROGRAM = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const MEMO = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const USDC_DEVNET = new PublicKey("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
const NOW = 1790000000;

const payer = Keypair.fromSeed(new Uint8Array(32).fill(7));
const facilitator = Keypair.fromSeed(new Uint8Array(32).fill(9));
const merchant = Keypair.fromSeed(new Uint8Array(32).fill(3)).publicKey;
const ata = (owner: PublicKey) =>
  PublicKey.findProgramAddressSync([owner.toBuffer(), TOKEN.toBuffer(), USDC_DEVNET.toBuffer()], ATA_PROGRAM)[0];

function transferChecked(amount: bigint, decimals = 6, dest = ata(merchant)) {
  const data = Buffer.alloc(10);
  data[0] = 12;
  data.writeBigUInt64LE(amount, 1);
  data[9] = decimals;
  return new TransactionInstruction({
    programId: TOKEN,
    keys: [
      { pubkey: ata(payer.publicKey), isSigner: false, isWritable: true },
      { pubkey: USDC_DEVNET, isSigner: false, isWritable: false },
      { pubkey: dest, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function buildTx(opts: { cuPrice?: number; amount?: bigint; extra?: TransactionInstruction[]; dest?: PublicKey } = {}) {
  const msg = new TransactionMessage({
    payerKey: facilitator.publicKey,
    recentBlockhash: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi",
    instructions: [
      ComputeBudgetProgram.setComputeUnitLimit({ units: 20000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: opts.cuPrice ?? 1 }),
      transferChecked(opts.amount ?? 10000n, 6, opts.dest),
      new TransactionInstruction({ programId: MEMO, keys: [], data: Buffer.from("order-42") }),
      ...(opts.extra ?? []),
    ],
  }).compileToV0Message();
  const tx = new VersionedTransaction(msg);
  tx.sign([payer]); // client signs; fee payer slot stays empty for the facilitator
  return Buffer.from(tx.serialize()).toString("base64");
}

const accepted = {
  scheme: "exact",
  network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  amount: "10000",
  asset: USDC_DEVNET.toBase58(),
  payTo: merchant.toBase58(),
  maxTimeoutSeconds: 60,
  extra: { feePayer: facilitator.publicKey.toBase58() },
};
const payload = (tx: string) =>
  b64({ x402Version: 2, resource: { url: "https://api.example.com/sol" }, accepted, payload: { transaction: tx } });

describe("SVM exact", () => {
  it("parser agrees with @solana/web3.js on a generated v0 transaction", () => {
    const tx64 = buildTx();
    const ours = parseTransaction(Buffer.from(tx64, "base64"));
    const theirs = VersionedTransaction.deserialize(Buffer.from(tx64, "base64"));
    expect(ours.version).toBe(0);
    expect(ours.accountKeys).toEqual(theirs.message.staticAccountKeys.map((k) => k.toBase58()));
    expect(ours.recentBlockhash).toBe(theirs.message.recentBlockhash);
    expect(ours.instructions.length).toBe(theirs.message.compiledInstructions.length);
    expect(Buffer.from(ours.messageBytes)).toEqual(Buffer.from(theirs.message.serialize()));
  });

  it("derives associated token accounts like web3.js", () => {
    expect(associatedTokenAddress(merchant.toBase58(), USDC_DEVNET.toBase58())).toBe(ata(merchant).toBase58());
  });

  it("explains a well-formed x402 SVM payment", () => {
    const d = dec(payload(buildTx()), NOW);
    expect(d.kind).toBe("x402.payment-payload");
    expect(d.summary).toBe(
      `Solana transaction that pays 0.01 USDC on Solana Devnet from ${payer.publicKey.toBase58().slice(0, 6)}…${payer.publicKey.toBase58().slice(-4)} to ${merchant.toBase58().slice(0, 6)}…${merchant.toBase58().slice(-4)} (its USDC account), with ${facilitator.publicKey.toBase58().slice(0, 6)}…${facilitator.publicKey.toBase58().slice(-4)} as fee payer. Payer signature valid; fee payer signs at settlement.`,
    );
    expect(codes(d)).toEqual(
      expect.arrayContaining(["SIG_VALID", "SVM_FEE_PAYER_UNSIGNED", "PAYTO_MATCHES", "AMOUNT_MATCHES", "SVM_MEMO"]),
    );
    expect(d.flags.filter((f) => f.level === "danger" || f.level === "warn")).toEqual([]);
    const ixs = d.sections.find((s) => s.title === "Instructions")!.fields.map((f) => f.value);
    expect(ixs[0]).toBe("Set compute unit limit to 20,000");
    expect(ixs[1]).toBe("Set priority fee to 1 microlamports per compute unit");
    expect(ixs[2]).toMatch(/^TransferChecked 0.01 USDC from token account /);
    expect(ixs[3]).toBe('Memo "order-42"');
  });

  it("flags a compute unit price above 5,000,000 microlamports", () => {
    const d = dec(payload(buildTx({ cuPrice: 50_000_000 })), NOW);
    expect(flagOf(d, "SVM_CU_PRICE_HIGH")?.message).toContain("50,000,000 microlamports per CU, above x402's cap of 5,000,000");
  });

  it("flags unknown programs and wrong destination", () => {
    const rogue = new TransactionInstruction({
      programId: Keypair.fromSeed(new Uint8Array(32).fill(5)).publicKey,
      keys: [],
      data: Buffer.from([1, 2, 3]),
    });
    const d = dec(payload(buildTx({ extra: [rogue], dest: ata(Keypair.fromSeed(new Uint8Array(32).fill(4)).publicKey) })), NOW);
    expect(codes(d)).toEqual(expect.arrayContaining(["SVM_UNKNOWN_PROGRAM", "PAYTO_MISMATCH"]));
  });

  it("tampered transaction bytes fail the payer signature", () => {
    const bytes = Buffer.from(buildTx(), "base64");
    const at = bytes.indexOf(Buffer.from("order-42"));
    bytes[at] ^= 0x01; // flip a memo byte: "order-42" -> "nrder-42"
    const d = dec(payload(bytes.toString("base64")), NOW);
    expect(flagOf(d, "SIG_INVALID")?.level).toBe("danger");
  });

  it("overpayment is caught", () => {
    expect(codes(dec(payload(buildTx({ amount: 20000n })), NOW))).toContain("AMOUNT_OVERPAY");
  });

  it("decodes a bare base64 legacy transaction", () => {
    const t = new Transaction({ feePayer: facilitator.publicKey, recentBlockhash: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi" });
    t.add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 20000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }),
      transferChecked(10000n),
    );
    t.partialSign(payer);
    const raw = t.serialize({ requireAllSignatures: false }).toString("base64");
    const d = dec(raw, NOW);
    expect(d.kind).toBe("svm.transaction");
    expect(d.summary).toMatch(/^Solana transaction that pays 0.01 USDC on Solana Devnet/);
    expect(codes(d)).toContain("SIG_VALID");
  });

  it("flags the fee payer acting as the transfer authority", () => {
    const msg = new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi",
      instructions: [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 20000 }),
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }),
        transferChecked(10000n),
      ],
    }).compileToV0Message();
    const tx = new VersionedTransaction(msg);
    const d = dec(Buffer.from(tx.serialize()).toString("base64"), NOW);
    expect(codes(d)).toContain("SVM_FEE_PAYER_IS_AUTHORITY");
  });
});
