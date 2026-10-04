import { describe, it, expect } from "vitest";
import { hashTypedData, getAddress, recoverTypedDataAddress, keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { typedDataDigest, typedDataHash, recoverAddress, checksumAddress, encodeType, keccakUtf8, makeRecoverer } from "../src/eip712.js";
import { ANVIL_0, TWA_TYPES, USDC_BASE_SEPOLIA } from "./helpers.js";

const hex = (b: Uint8Array) => "0x" + Buffer.from(b).toString("hex");
const domain = { name: "USDC", version: "2", chainId: 84532, verifyingContract: USDC_BASE_SEPOLIA as `0x${string}` };
const message = {
  from: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
  to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
  value: 10000n,
  validAfter: 1740672089n,
  validBefore: 1740672154n,
  nonce: "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480",
} as const;

describe("eip712 vs viem", () => {
  it("flat TransferWithAuthorization digest matches viem", () => {
    const ours = typedDataDigest(domain, "TransferWithAuthorization", [...TWA_TYPES.TransferWithAuthorization], { ...message });
    expect(hex(ours)).toBe(hashTypedData({ domain, types: TWA_TYPES, primaryType: "TransferWithAuthorization", message }));
  });

  it("accepts decimal strings the way x402 payloads carry them", () => {
    const strMsg = { ...message, value: "10000", validAfter: "1740672089", validBefore: "1740672154" };
    const ours = typedDataDigest(domain, "TransferWithAuthorization", [...TWA_TYPES.TransferWithAuthorization], strMsg);
    expect(hex(ours)).toBe(hashTypedData({ domain, types: TWA_TYPES, primaryType: "TransferWithAuthorization", message }));
  });

  it("nested Permit2 witness digest matches viem", () => {
    const types = {
      PermitWitnessTransferFrom: [
        { name: "permitted", type: "TokenPermissions" },
        { name: "spender", type: "address" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
        { name: "witness", type: "Witness" },
      ],
      TokenPermissions: [
        { name: "token", type: "address" },
        { name: "amount", type: "uint256" },
      ],
      Witness: [
        { name: "to", type: "address" },
        { name: "validAfter", type: "uint256" },
      ],
    } as const;
    const d = { name: "Permit2", chainId: 8453, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" as const };
    const m = {
      permitted: { token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", amount: 1234n },
      spender: "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
      nonce: 77n,
      deadline: 1800000000n,
      witness: { to: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", validAfter: 1n },
    } as const;
    expect(encodeType("PermitWitnessTransferFrom", types as never)).toBe(
      "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)",
    );
    expect(hex(typedDataHash(d, types as never, "PermitWitnessTransferFrom", m as never))).toBe(
      hashTypedData({ domain: d, types, primaryType: "PermitWitnessTransferFrom", message: m }),
    );
  });

  it("handles arrays and string/bytes/bool members like viem", () => {
    const types = {
      Mail: [
        { name: "subject", type: "string" },
        { name: "tags", type: "string[]" },
        { name: "blob", type: "bytes" },
        { name: "urgent", type: "bool" },
        { name: "to", type: "Person[]" },
      ],
      Person: [
        { name: "name", type: "string" },
        { name: "wallet", type: "address" },
      ],
    } as const;
    const m = {
      subject: "hi",
      tags: ["a", "b"],
      blob: "0xdeadbeef",
      urgent: true,
      to: [{ name: "Bob", wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" }],
    } as const;
    const d = { name: "Mail", version: "1", chainId: 1 };
    expect(hex(typedDataHash(d, types as never, "Mail", m as never))).toBe(
      hashTypedData({ domain: d, types, primaryType: "Mail", message: m }),
    );
  });

  it("checksums addresses like viem", () => {
    for (const a of [
      "0x857b06519e91e3a54538791bdbb0e22373e36b66",
      "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
      "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
    ]) {
      expect(checksumAddress(a)).toBe(getAddress(a));
    }
  });

  it("recovers the signer exactly like viem, for v = 27/28 and v = 0/1", async () => {
    const acct = privateKeyToAccount(ANVIL_0);
    const sig = await acct.signTypedData({ domain, types: TWA_TYPES, primaryType: "TransferWithAuthorization", message });
    const digest = typedDataDigest(domain, "TransferWithAuthorization", [...TWA_TYPES.TransferWithAuthorization], { ...message });
    expect(recoverAddress(digest, sig)).toBe(acct.address);
    expect(
      await recoverTypedDataAddress({ domain, types: TWA_TYPES, primaryType: "TransferWithAuthorization", message, signature: sig }),
    ).toBe(acct.address);
    const v = parseInt(sig.slice(-2), 16);
    const low = sig.slice(0, -2) + (v - 27).toString(16).padStart(2, "0");
    expect(recoverAddress(digest, low)).toBe(acct.address);
    expect(recoverAddress(digest, sig.slice(2))).toBe(acct.address); // no 0x prefix
  });

  it("recovers the real x402 fixture signer under the USDC domain and not under 'USD Coin'", () => {
    const sig =
      "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c";
    const good = typedDataDigest(domain, "TransferWithAuthorization", [...TWA_TYPES.TransferWithAuthorization], { ...message });
    const bad = typedDataDigest({ ...domain, name: "USD Coin" }, "TransferWithAuthorization", [...TWA_TYPES.TransferWithAuthorization], {
      ...message,
    });
    expect(recoverAddress(good, sig)).toBe(message.from);
    expect(recoverAddress(bad, sig)).not.toBe(message.from);
  });

  it("returns null for malformed signatures", () => {
    expect(recoverAddress(new Uint8Array(32), "0x1234")).toBeNull();
    expect(recoverAddress(new Uint8Array(32), "0x" + "00".repeat(64) + "1f")).toBeNull();
  });

  it("keccakUtf8 matches viem keccak256(toHex(str))", () => {
    expect(keccakUtf8("hello~~world")).toBe(keccak256(toHex("hello~~world")));
  });

  it("makeRecoverer (fast multi-digest path used by the domain search) agrees with full recovery", async () => {
    const acct = privateKeyToAccount(ANVIL_0);
    const sig = await acct.signTypedData({ domain, types: TWA_TYPES, primaryType: "TransferWithAuthorization", message });
    const rec = makeRecoverer(sig)!;
    for (const name of ["USDC", "USD Coin", "x"]) {
      const dg = typedDataDigest({ ...domain, name }, "TransferWithAuthorization", [...TWA_TYPES.TransferWithAuthorization], {
        ...message,
      });
      expect(rec(dg)).toBe(recoverAddress(dg, sig));
    }
    expect(makeRecoverer("0x1234")).toBeNull();
  });
});
