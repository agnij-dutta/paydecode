import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { decode, detect } from "../src/index.js";
import { codes, flagOf, dec } from "./helpers.js";

// Verbatim from IETF draft-httpauth-payment-01 (tempoxyz/mpp-specs).
const MPP_CHALLENGE = `WWW-Authenticate: Payment id="x7Tg2pLqR9mKvNwY3hBcZa",
    realm="api.example.com",
    method="example",
    intent="charge",
    expires="2025-01-15T12:05:00Z",
    request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QiLCJyZWNpcGllbnQiOiJhY2N0XzEyMyJ9"`;
const MPP_CREDENTIAL =
  "Authorization: Payment eyJjaGFsbGVuZ2UiOnsiaWQiOiJ4N1RnMnBMcVI5bUt2TndZM2hCY1phIiwicmVhbG0iOiJhcGkuZXhhbXBsZS5jb20iLCJtZXRob2QiOiJleGFtcGxlIiwiaW50ZW50IjoiY2hhcmdlIiwicmVxdWVzdCI6ImV5SmhiVzkxYm5RaU9pSXhNREF3SWl3aVkzVnljbVZ1WTNraU9pSlZVMFFpTENKeVpXTnBjR2xsYm5RaU9pSmhZMk4wWHpFeU15SjkiLCJleHBpcmVzIjoiMjAyNS0wMS0xNVQxMjowNTowMFoifSwicGF5bG9hZCI6eyJwcm9vZiI6IjB4YWJjMTIzLi4uIn19";
const BEFORE_EXPIRY = Date.parse("2025-01-15T12:00:00Z") / 1000;

// Verbatim from agentic-commerce-protocol examples/unreleased/examples.delegate_payment.json
const ACP_REQUEST = {
  payment_method: { type: "card", card_number_type: "fpan", virtual: false, number: "4242424242424242", exp_month: "11", exp_year: "2026", name: "Jane Doe", cvc: "223", checks_performed: ["avs", "cvv"], iin: "424242", display_card_funding_type: "credit", display_wallet_type: "apple_pay", display_brand: "visa", display_last4: "4242", metadata: { issuing_bank: "temp" } },
  allowance: { reason: "one_time", max_amount: 2000, currency: "usd", checkout_session_id: "csn_01HV3P3XYZ9ABC", merchant_id: "acme_store", expires_at: "2025-10-09T07:20:50.52Z" },
  billing_address: { name: "Ada Lovelace", line_one: "1234 Chat Road", line_two: "", city: "San Francisco", state: "CA", country: "US", postal_code: "94131" },
  risk_signals: [{ type: "card_testing", score: 10, action: "manual_review" }],
  metadata: { campaign: "q4", source: "chatgpt_checkout" },
};

// Format from visa/trusted-agent-protocol tap-agent/agent_app.py
const TAP = `Signature-Input: sig2=("@authority" "@path"); created=1735689600; expires=1735690080; keyId="primary-ed25519"; alg="ed25519"; nonce="e8N7S2MFd"; tag="agent-payer-auth"`;

describe("MPP", () => {
  it("challenge (multi-line WWW-Authenticate from the IETF draft)", () => {
    const d = dec(MPP_CHALLENGE, BEFORE_EXPIRY);
    expect(d.kind).toBe("mpp.challenge");
    expect(d.summary).toBe(
      "api.example.com asks for a one-time charge of $10.00 USD to acct_123 via 'example', offer expires 15 Jan 2025, 12:05:00 UTC. Pay by retrying the request with an Authorization: Payment credential.",
    );
  });

  it("expired challenge", () => {
    expect(flagOf(dec(MPP_CHALLENGE, BEFORE_EXPIRY + 3600), "MPP_EXPIRED")?.level).toBe("danger");
  });

  it("credential: echoed challenge decoded, proof not verified", () => {
    const d = dec(MPP_CREDENTIAL, BEFORE_EXPIRY);
    expect(d.kind).toBe("mpp.credential");
    expect(d.summary).toBe(
      "MPP credential answering challenge x7Tg2pLq…BcZa from api.example.com: claims to pay a one-time charge of $10.00 USD to acct_123 via 'example'. Proof not verified (no key).",
    );
    expect(codes(d)).toContain("MPP_PROOF_UNVERIFIED");
  });

  it("receipt", () => {
    const r = Buffer.from(JSON.stringify({ status: "success", method: "tempo", timestamp: "2025-01-15T12:04:00Z", reference: "0xabc123def4567890" })).toString("base64url");
    const d = dec(`Payment-Receipt: ${r}`, BEFORE_EXPIRY);
    expect(d.summary).toBe("Receipt: payment succeeded via 'tempo' at 15 Jan 2025, 12:04:00 UTC, reference 0xabc123de…567890.");
  });

  it("tempo challenge with token decimals in methodDetails", () => {
    const req = Buffer.from(JSON.stringify({ amount: "1000000", currency: "0x3600000000000000000000000000000000000000", recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00", methodDetails: { chainId: 5042, decimals: 6 } })).toString("base64url");
    const d = dec(`WWW-Authenticate: Payment id="abc", realm="api.x", method="usdc", intent="charge", request="${req}"`, BEFORE_EXPIRY);
    expect(d.summary).toContain("a one-time charge of 1.00 USDC to 0x742d…fE00 via 'usdc'");
  });
});

describe("ACP", () => {
  it("delegate payment request: allowance in English, raw PAN flagged", () => {
    const d = dec(JSON.stringify(ACP_REQUEST), Date.parse("2025-10-09T07:00:00Z") / 1000);
    expect(d.kind).toBe("acp.delegate-payment");
    expect(d.summary).toBe("Asks the PSP to vault visa ending 4242 so the agent can charge up to $20.00 USD at merchant 'acme_store' for checkout csn_01HV3P3XYZ9ABC, once.");
    expect(flagOf(d, "ACP_RAW_PAN")?.level).toBe("danger");
    expect(codes(d)).toContain("ACP_RISK_SIGNAL");
    expect(JSON.stringify(d.sections)).not.toContain("4242424242424242");
  });

  it("expired allowance and vault token response", () => {
    expect(codes(dec(JSON.stringify(ACP_REQUEST.allowance), Date.parse("2025-10-10T00:00:00Z") / 1000))).toContain("ACP_ALLOWANCE_EXPIRED");
    const t = dec(JSON.stringify({ id: "vt_01J8Z3WXYZ9ABC", created: "2025-09-29T11:00:00Z", metadata: { source: "agent_checkout" } }), 0);
    expect(t.kind).toBe("acp.vault-token");
  });
});

describe("Visa TAP", () => {
  it("Signature-Input with the agent-payer-auth tag", () => {
    const d = dec(TAP, 1735689700);
    expect(d.kind).toBe("visa-tap.signature");
    expect(d.summary).toBe(
      `Visa Trusted Agent Protocol signature: agent key 'primary-ed25519' signs "@authority" and "@path" to pay at checkout, valid until 1 Jan 2025, 00:08:00 UTC. Not verified (no key).`,
    );
    expect(codes(d)).toContain("TAP_UNVERIFIED");
    expect(codes(d)).not.toContain("TAP_LONG_WINDOW");
  });

  it("expired and weakly scoped signatures", () => {
    const d = dec(`sig1=("@path"); created=1735689600; expires=1735699600; keyid="k"; tag="agent-browser-auth"`, 1735699700);
    expect(codes(d)).toEqual(expect.arrayContaining(["TAP_EXPIRED", "TAP_LONG_WINDOW", "TAP_WEAK_COVERAGE", "TAP_NO_NONCE"]));
  });
});

describe("unrecognized input", () => {
  it("never throws, and explains what it saw", () => {
    expect(decode("").kind).toBe("unknown");
    expect(decode("hello world").summary).toContain("Not JSON, base64, a JWT/SD-JWT, or a known payment header");
    const j = decode(JSON.stringify({ foo: 1, bar: [1, 2] }));
    expect(j.kind).toBe("unknown");
    expect(j.summary).toBe("This is valid JSON, but no known payment schema matched it. The parsed JSON is below.");
    expect(j.raw).toEqual({ foo: 1, bar: [1, 2] });
    const b = decode(Buffer.from(JSON.stringify({ x402Version: 2, hello: true })).toString("base64"));
    expect(b.summary).toBe("This is base64-encoded JSON, but no known schema matched it. Here's the decoded JSON.".replace("known schema", "known payment schema"));
    expect(codes(b)).toContain("X402_PARTIAL");
    expect(decode("0x" + "ab".repeat(65)).summary).toContain("bare 65-byte ECDSA signature");
    expect(decode("0x857b06519E91e3A54538791bDbb0E22373e36b66").summary).toBe("That's an EVM address, not a payment artifact.");
    expect(decode(Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]).toString("base64")).summary).toContain("8 bytes of binary");
    // @ts-expect-error runtime garbage
    expect(decode(undefined).kind).toBe("unknown");
  });

  it("detect() on assorted inputs", () => {
    expect(detect(TAP)).toEqual({ kind: "visa-tap.signature", header: "signature-input", encoding: "auth-params" });
    expect(detect("nope").kind).toBe("unknown");
  });

  it("is fast enough for keystroke-by-keystroke use", () => {
    const fx = readFileSync(new URL("./fixtures/ap2-x402-bundle.json", import.meta.url), "utf8");
    const t = performance.now();
    for (let i = 0; i < 5; i++) decode(fx, { now: 1777343000 });
    expect((performance.now() - t) / 5).toBeLessThan(500);
  });
});
