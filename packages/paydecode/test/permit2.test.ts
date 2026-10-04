import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { b64, codes, flagOf, dec, ANVIL_0 } from "./helpers.js";

const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3" as const;
const PROXY = "0x402085c248EeA27D92E8b30b2C58ed07f9E20001";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY_TO = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const NOW = 1790000000;

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

async function permit2Payload(opts: { spender?: string; chainId?: number; network?: string } = {}) {
  const acct = privateKeyToAccount(ANVIL_0);
  const message = {
    permitted: { token: USDC_BASE as `0x${string}`, amount: 2500000n },
    spender: (opts.spender ?? PROXY) as `0x${string}`,
    nonce: 123456789n,
    deadline: BigInt(NOW + 300),
    witness: { to: PAY_TO as `0x${string}`, validAfter: BigInt(NOW - 600) },
  };
  const signature = await acct.signTypedData({
    domain: { name: "Permit2", chainId: opts.chainId ?? 8453, verifyingContract: PERMIT2 },
    types,
    primaryType: "PermitWitnessTransferFrom",
    message,
  });
  return {
    x402Version: 2,
    accepted: {
      scheme: "exact",
      network: opts.network ?? "eip155:8453",
      amount: "2500000",
      asset: USDC_BASE,
      payTo: PAY_TO,
      maxTimeoutSeconds: 300,
      extra: { assetTransferMethod: "permit2", name: "USD Coin", version: "2" },
    },
    payload: {
      signature,
      permit2Authorization: {
        from: acct.address,
        permitted: { token: USDC_BASE, amount: "2500000" },
        spender: message.spender,
        nonce: String(message.nonce),
        deadline: String(message.deadline),
        witness: { to: PAY_TO, validAfter: String(message.witness.validAfter) },
      },
    },
  };
}

describe("x402 exact / Permit2", () => {
  it("decodes and verifies a Permit2 payload signed in-test with viem", async () => {
    const d = dec(b64(await permit2Payload()), NOW);
    expect(d.kind).toBe("x402.payment-payload");
    expect(d.summary).toBe(
      "Permit2 authorization for 0xf39F…2266 to pay 2.50 USDC on Base to 0x2096…287C through the x402 proxy, valid until 21 Sep 2026. Signature valid.",
    );
    expect(codes(d)).toEqual(
      expect.arrayContaining(["SIG_VALID", "PERMIT2_SPENDER_OK", "AMOUNT_MATCHES", "PAYTO_MATCHES", "PERMIT2_APPROVAL_NEEDED"]),
    );
    expect(d.flags.filter((f) => f.level === "danger")).toEqual([]);
  });

  it("flags a spender that is not the x402 proxy (signature still valid)", async () => {
    const d = dec(b64(await permit2Payload({ spender: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" })), NOW);
    expect(codes(d)).toContain("SIG_VALID");
    expect(flagOf(d, "PERMIT2_SPENDER_NOT_PROXY")?.message).toContain("Spender is 0x7099…79C8, not the x402 Permit2 proxy");
  });

  it("detects a Permit2 signature made for another chain", async () => {
    const d = dec(b64(await permit2Payload({ chainId: 84532 })), NOW);
    expect(flagOf(d, "SIG_WRONG_CHAIN")?.message).toContain("Base Sepolia (chainId 84532), not Base");
  });

  it("tampered witness recipient breaks the signature", async () => {
    const p = await permit2Payload();
    p.payload.permit2Authorization.witness.to = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    const d = dec(b64(p), NOW);
    expect(codes(d)).toEqual(expect.arrayContaining(["SIG_INVALID", "PAYTO_MISMATCH"]));
  });

  it("expired deadline", async () => {
    expect(codes(dec(b64(await permit2Payload()), NOW + 3600))).toContain("AUTH_EXPIRED");
  });

  it("window is inclusive at both ends, like Permit2 (deadline) and the x402 proxy (validAfter)", async () => {
    const p = b64(await permit2Payload());
    // Permit2 reverts only when block.timestamp > deadline.
    expect(codes(dec(p, NOW + 300))).not.toContain("AUTH_EXPIRED");
    expect(dec(p, NOW + 300).summary).not.toContain("(expired");
    expect(codes(dec(p, NOW + 301))).toContain("AUTH_EXPIRED");
    // x402BasePermit2Proxy reverts only when block.timestamp < witness.validAfter.
    expect(codes(dec(p, NOW - 600))).not.toContain("AUTH_NOT_YET_VALID");
    expect(codes(dec(p, NOW - 601))).toContain("AUTH_NOT_YET_VALID");
  });
});
