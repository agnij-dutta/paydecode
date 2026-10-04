import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { decode, detect } from "../src/index.js";
import { FIX, X402_NOW, b64, unb64, codes, flagOf, dec, USDC_BASE_SEPOLIA, ANVIL_0, TWA_TYPES } from "./helpers.js";

const V2_SIG: string = FIX.x402_v2_http["PAYMENT-SIGNATURE"][0];
const V2_REQ: string = FIX.x402_v2_http["PAYMENT-REQUIRED"][0];
const V1_PAY: string = FIX.x402_v1_http["X-PAYMENT"][0];

async function signedPayload(opts: { signName: string; extraName: string; value?: bigint; validBefore?: bigint; to?: string }) {
  const acct = privateKeyToAccount(ANVIL_0);
  const auth = {
    from: acct.address,
    to: (opts.to ?? "0x209693Bc6afc0C5328bA36FaF03C514EF312287C") as `0x${string}`,
    value: opts.value ?? 10000n,
    validAfter: 1740672089n,
    validBefore: opts.validBefore ?? 1740672154n,
    nonce: "0x1111111111111111111111111111111111111111111111111111111111111111" as const,
  };
  const signature = await acct.signTypedData({
    domain: { name: opts.signName, version: "2", chainId: 84532, verifyingContract: USDC_BASE_SEPOLIA },
    types: TWA_TYPES,
    primaryType: "TransferWithAuthorization",
    message: auth,
  });
  return {
    x402Version: 2,
    accepted: {
      scheme: "exact",
      network: "eip155:84532",
      amount: "10000",
      asset: USDC_BASE_SEPOLIA,
      payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      maxTimeoutSeconds: 60,
      extra: { name: opts.extraName, version: "2" },
    },
    payload: {
      signature,
      authorization: { ...auth, value: String(auth.value), validAfter: String(auth.validAfter), validBefore: String(auth.validBefore) },
    },
  };
}

describe("x402 fixtures", () => {
  it("v1 X-PAYMENT: decodes, infers Base Sepolia USDC from the signature, verifies the signer", () => {
    const d = dec(`X-PAYMENT: ${V1_PAY}`, X402_NOW);
    expect(d.kind).toBe("x402.payment-payload");
    expect(d.title).toBe("x402 payment (v1, exact)");
    expect(d.summary).toBe(
      "Authorizes 0x857b…6b66 to pay 0.01 USDC on Base Sepolia to 0x2096…287C, valid for 65 seconds starting 27 Feb 2025. Signature valid.",
    );
    expect(codes(d)).toContain("SIG_VALID");
    expect(codes(d)).toContain("ASSET_INFERRED");
    expect(codes(d)).not.toContain("AUTH_EXPIRED");
  });

  it("v2 PAYMENT-SIGNATURE: the headline summary, signature valid, amount + payTo cross-checked", () => {
    const d = dec(V2_SIG, X402_NOW);
    expect(d.kind).toBe("x402.payment-payload");
    expect(d.summary).toBe(
      "Authorizes 0x857b…6b66 to pay 0.01 USDC on Base Sepolia to 0x2096…287C, valid for 65 seconds starting 27 Feb 2025. Signature valid.",
    );
    expect(codes(d)).toEqual(expect.arrayContaining(["SIG_VALID", "AMOUNT_MATCHES", "PAYTO_MATCHES"]));
    expect(d.flags.filter((f) => f.level === "danger")).toEqual([]);
  });

  it("v2 PAYMENT-REQUIRED header", () => {
    const d = dec(`PAYMENT-REQUIRED: ${V2_REQ}`, X402_NOW);
    expect(d.kind).toBe("x402.payment-required");
    expect(d.summary).toBe(
      'Server asks for 0.01 USDC on Base Sepolia to 0x2096…287C (exact, EIP-3009) to access https://api.example.com/premium-data (Access to premium market data). Server message: "PAYMENT-SIGNATURE header is required".',
    );
    expect(d.flags.filter((f) => f.level === "danger" || f.level === "warn")).toEqual([]);
  });

  for (const [ver, key] of [
    ["v1", "X-PAYMENT-RESPONSE"],
    ["v2", "PAYMENT-RESPONSE"],
  ] as const) {
    it(`${ver} ${key}: success and insufficient_funds`, () => {
      const group = ver === "v1" ? FIX.x402_v1_http : FIX.x402_v2_http;
      const ok = dec(`${key}: ${group[key][0]}`, X402_NOW);
      expect(ok.kind).toBe("x402.settle-response");
      expect(ok.summary).toBe("Settlement succeeded on Base Sepolia: transaction 0x12345678…abcdef, paid by 0x857b…6b66.");
      expect(codes(ok)).toEqual(expect.arrayContaining(["SETTLED", "PLACEHOLDER_TX"]));
      const bad = dec(group[key][1], X402_NOW);
      expect(bad.summary).toContain("Settlement failed on Base Sepolia: insufficient_funds (the payer's wallet doesn't hold enough of the asset)");
      expect(flagOf(bad, "SETTLE_FAILED")?.level).toBe("danger");
    });
  }
});

describe("EIP-3009 domain diagnosis", () => {
  it("positive: the fixture signature matches Base Sepolia USDC's real domain ('USDC')", () => {
    const d = dec(V2_SIG, X402_NOW);
    expect(flagOf(d, "SIG_VALID")).toBeDefined();
    expect(flagOf(d, "EIP712_DOMAIN_MISMATCH")).toBeUndefined();
  });

  it("negative: requirements say 'USD Coin' and the client signed with it -> rejected on-chain", async () => {
    const p = await signedPayload({ signName: "USD Coin", extraName: "USD Coin" });
    const d = dec(b64(p), X402_NOW);
    const f = flagOf(d, "EIP712_DOMAIN_MISMATCH");
    expect(f?.level).toBe("danger");
    expect(f?.message).toContain("Signed with name 'USD Coin' (copied from the requirements' extra) but Base Sepolia USDC's domain name is 'USDC'");
    expect(d.summary).toContain("Signature will be rejected on-chain: signed with name 'USD Coin' but Base Sepolia USDC's domain name is 'USDC'.");
    expect(codes(d)).not.toContain("SIG_VALID");
  });

  it("negative: requirements are right but the client signed with 'USD Coin' anyway -> found by domain search", async () => {
    const p = await signedPayload({ signName: "USD Coin", extraName: "USDC" });
    const d = dec(b64(p), X402_NOW);
    expect(flagOf(d, "EIP712_DOMAIN_MISMATCH")?.message).toMatch(/^Signed with name 'USD Coin' but Base Sepolia USDC's domain name is 'USDC'/);
  });

  it("the fixture's real signature with extra.name edited to 'USD Coin' still verifies on-chain, but extra is flagged", () => {
    const p = unb64(V2_SIG);
    p.accepted.extra.name = "USD Coin";
    const d = dec(b64(p), X402_NOW);
    expect(codes(d)).toContain("SIG_VALID");
    expect(flagOf(d, "EXTRA_DOMAIN_WRONG")?.level).toBe("warn");
  });

  it("PaymentRequired advertising the wrong domain is flagged before anyone signs", () => {
    const r = unb64(V2_REQ);
    r.accepts[0].extra.name = "USD Coin";
    const d = dec(b64(r), X402_NOW);
    expect(flagOf(d, "REQUIREMENTS_DOMAIN_WRONG")?.message).toContain("extra.name is 'USD Coin' but Base Sepolia USDC's on-chain EIP-712 domain name is 'USDC'");
  });
});

describe("EIP-3009 tampering and validity", () => {
  it("tampered value: signature no longer recovers to from", () => {
    const p = unb64(V2_SIG);
    p.payload.authorization.value = "1000000";
    p.accepted.amount = "1000000";
    const d = dec(b64(p), X402_NOW);
    expect(flagOf(d, "SIG_INVALID")?.level).toBe("danger");
    expect(d.summary).toContain("Signature INVALID.");
    expect(d.summary).toContain("1.00 USDC");
  });

  it("tampered signature byte", () => {
    const p = unb64(V2_SIG);
    const s: string = p.payload.signature;
    p.payload.signature = s.slice(0, 10) + (s[10] === "a" ? "b" : "a") + s.slice(11);
    expect(codes(dec(b64(p), X402_NOW))).toContain("SIG_INVALID");
  });

  it("truncated signature is called malformed", () => {
    const p = unb64(V2_SIG);
    p.payload.signature = p.payload.signature.slice(0, 40);
    expect(codes(dec(b64(p), X402_NOW))).toContain("SIG_MALFORMED");
  });

  it("expired authorization (evaluated against real time)", () => {
    const d = decode(V2_SIG);
    const f = flagOf(d, "AUTH_EXPIRED");
    expect(f?.level).toBe("danger");
    expect(d.summary).toMatch(/\(expired .* ago\)\. Signature valid\.$/);
  });

  it("not yet valid", () => {
    expect(codes(dec(V2_SIG, 1740672000))).toContain("AUTH_NOT_YET_VALID");
  });

  it("unusually long window", async () => {
    const p = await signedPayload({ signName: "USDC", extraName: "USDC", validBefore: 1740672089n + 7n * 86400n });
    const d = dec(b64(p), X402_NOW);
    expect(codes(d)).toContain("SIG_VALID");
    expect(flagOf(d, "AUTH_WINDOW_LONG")?.message).toContain("7 days");
  });

  it("to != accepted.payTo and value > accepted.amount", async () => {
    const p = await signedPayload({ signName: "USDC", extraName: "USDC", value: 50000n, to: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" });
    const d = dec(b64(p), X402_NOW);
    expect(codes(d)).toContain("SIG_VALID");
    expect(flagOf(d, "PAYTO_MISMATCH")?.message).toBe(
      "Pays 0x7099…79C8 but the requirements say payTo is 0x2096…287C. Money would go to the wrong address; the server should refuse it.",
    );
    expect(flagOf(d, "AMOUNT_OVERPAY")?.message).toContain("overpay by 0.04 USDC");
  });

  it("unknown asset", () => {
    const p = unb64(V2_SIG);
    p.accepted.asset = "0x1111111111111111111111111111111111111111";
    const d = dec(b64(p), X402_NOW);
    expect(codes(d)).toContain("UNKNOWN_ASSET");
    expect(d.summary).toContain("10000 atomic units of 0x1111…1111");
  });

  it("right token address, wrong chain", () => {
    const p = unb64(V2_SIG);
    p.accepted.network = "eip155:8453";
    const d = dec(b64(p), X402_NOW);
    expect(codes(d)).toEqual(expect.arrayContaining(["ASSET_WRONG_CHAIN", "SIG_WRONG_CHAIN"]));
  });
});

describe("x402 containers and transports", () => {
  it("facilitator /verify body with paymentRequirements", () => {
    const p = unb64(V2_SIG);
    const body = { x402Version: 2, paymentPayload: p, paymentRequirements: p.accepted };
    const d = dec(JSON.stringify(body), X402_NOW);
    expect(d.kind).toBe("x402.facilitator-request");
    expect(d.summary).toMatch(/^Facilitator request: Authorizes 0x857b…6b66 to pay 0.01 USDC/);
  });

  it("facilitator v1 /verify body cross-checks payTo from paymentRequirements", () => {
    const p = unb64(V1_PAY);
    const req = { scheme: "exact", network: "base-sepolia", maxAmountRequired: "10000", resource: "https://x/y", description: "", mimeType: "", payTo: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", maxTimeoutSeconds: 60, asset: USDC_BASE_SEPOLIA, extra: { name: "USDC", version: "2" } };
    const d = dec(JSON.stringify({ x402Version: 1, paymentPayload: p, paymentRequirements: req }), X402_NOW);
    expect(codes(d)).toEqual(expect.arrayContaining(["SIG_VALID", "PAYTO_MISMATCH", "AMOUNT_MATCHES"]));
  });

  it("v1 402 body", () => {
    const body = { x402Version: 1, error: "X-PAYMENT header is required", accepts: [{ scheme: "exact", network: "base", maxAmountRequired: "2500000", resource: "https://api.example.com/report", description: "Weekly report", mimeType: "application/json", payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", maxTimeoutSeconds: 300, asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", extra: { name: "USD Coin", version: "2" } }] };
    const d = dec(JSON.stringify(body), X402_NOW);
    expect(d.summary).toBe(
      'Server asks for 2.50 USDC on Base to 0x2096…287C (exact, EIP-3009) to access https://api.example.com/report (Weekly report). Server message: "X-PAYMENT header is required".',
    );
  });

  it("full HTTP 402 response paste with header and body", () => {
    const http = `HTTP/1.1 402 Payment Required\nContent-Type: application/json\nPAYMENT-REQUIRED: ${V2_REQ}\n\n{"error":"pay up"}`;
    const d = dec(http, X402_NOW);
    expect(d.kind).toBe("x402.payment-required");
    expect(codes(d)).toContain("WRAPPED");
  });

  it("curl -H line", () => {
    const d = dec(`curl -s https://api.example.com/premium-data -H 'PAYMENT-SIGNATURE: ${V2_SIG}' -H "Accept: application/json"`, X402_NOW);
    expect(d.kind).toBe("x402.payment-payload");
    expect(codes(d)).toContain("SIG_VALID");
  });

  it("MCP _meta x402/payment wrapper", () => {
    const rpc = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_weather", arguments: {}, _meta: { "x402/payment": unb64(V2_SIG) } } };
    const d = dec(JSON.stringify(rpc), X402_NOW);
    expect(d.kind).toBe("x402.payment-payload");
    expect(d.title).toContain('inside MCP _meta["x402/payment"]');
    expect(codes(d)).toContain("SIG_VALID");
  });

  it("A2A metadata with requirements and a payload together", () => {
    const msg = { metadata: { "x402.payment.status": "payment-submitted", "x402.payment.required": unb64(V2_REQ), "x402.payment.payload": unb64(V2_SIG) } };
    const d = dec(JSON.stringify(msg), X402_NOW);
    expect(d.kind).toBe("container");
    if (d.kind === "container") expect(d.children?.map((c) => c.kind)).toEqual(["x402.payment-required", "x402.payment-payload"]);
  });

  it("/supported and verify responses", () => {
    const sup = { kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453" }, { x402Version: 2, scheme: "exact", network: "eip155:84532" }, { x402Version: 2, scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", extra: { feePayer: "FacPay111" } }], extensions: [], signers: { "eip155:*": ["0x1111111111111111111111111111111111111111"] } };
    expect(dec(JSON.stringify(sup), X402_NOW).summary).toBe("Facilitator supports 3 scheme/network pairs: exact (v2) on Base, Base Sepolia, and Solana.");
    const vr = dec(JSON.stringify({ isValid: false, invalidReason: "invalid_exact_evm_payload_signature", payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66" }), X402_NOW);
    expect(vr.summary).toContain("often a wrong domain name/version or chain");
  });

  it("detect() reports kind, header and encoding", () => {
    expect(detect(`X-PAYMENT: ${V1_PAY}`)).toEqual({ kind: "x402.payment-payload", header: "x-payment", encoding: "base64-json" });
    expect(detect(Buffer.from(V2_REQ, "base64").toString())).toEqual({ kind: "x402.payment-required", encoding: "json" });
  });
});
