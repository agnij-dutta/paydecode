import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { privateKeyToAccount } from "viem/accounts";
import { keccak256, toHex } from "viem";
import { decode, parseChain, sdHash } from "../src/index.js";
import { FIX, AP2_NOW, readFixture, codes, flagOf, dec, ANVIL_0, TWA_TYPES, USDC_BASE_SEPOLIA } from "./helpers.js";

const CHAIN: string = FIX.ap2_v02_open_plus_closed_payment_mandate_chain;
const bu = (b: Uint8Array | string) => Buffer.from(b).toString("base64url");

// ---- a tiny SD-JWT issuer for building chains in-test
const rootKey = new Uint8Array(32).fill(11);
const agentKey = new Uint8Array(32).fill(22);
const jwkOf = (sk: Uint8Array) => {
  const pub = p256.getPublicKey(sk, false);
  return { kty: "EC", crv: "P-256", x: bu(pub.slice(1, 33)), y: bu(pub.slice(33)) };
};
let saltN = 0;
const disclose = (value: unknown, name?: string) => {
  const raw = bu(JSON.stringify(name === undefined ? [`salt${++saltN}`, value] : [`salt${++saltN}`, name, value]));
  return { raw, digest: bu(sha256(new TextEncoder().encode(raw))) };
};
const sign = (header: object, payload: object, sk: Uint8Array) => {
  const input = `${bu(JSON.stringify(header))}.${bu(JSON.stringify(payload))}`;
  return `${input}.${bu(p256.sign(new TextEncoder().encode(input), sk))}`;
};
function buildChain(
  open: Record<string, unknown> | null,
  closed: Record<string, unknown> | null,
  opts: { closedSigner?: Uint8Array; skipSdHash?: boolean } = {},
) {
  const hops: string[] = [];
  if (open) {
    const d = disclose(open);
    hops.push(
      `${sign({ alg: "ES256", typ: "example+sd-jwt", kid: "root-1" }, { delegate_payload: [{ "...": d.digest }], _sd_alg: "sha-256" }, rootKey)}~${d.raw}~`,
    );
  }
  if (closed) {
    const d = disclose(closed);
    const prevSd = hops[0];
    const payload: Record<string, unknown> = {
      delegate_payload: [{ "...": d.digest }],
      iat: AP2_NOW - 10,
      aud: "credential-provider",
      nonce: "n-1",
      _sd_alg: "sha-256",
    };
    if (!opts.skipSdHash) payload.sd_hash = sdHash(prevSd);
    hops.push(`${sign({ alg: "ES256", typ: "kb+sd-jwt" }, payload, opts.closedSigner ?? agentKey)}~${d.raw}~`);
  }
  // AP2 joins hops with "~~": hop 1 keeps its own trailing "~" as the first "~" of the separator
  return hops.map((h, i) => (i < hops.length - 1 ? h.slice(0, -1) : h)).join("~~");
}
const openMandate = (cap: number, cnf = true) => ({
  vct: "mandate.payment.open.1",
  constraints: [
    { type: "payment.amount_range", currency: "USD", max: cap, min: 0 },
    { type: "payment.allowed_payees", allowed: [{ id: "merchant_1", name: "Demo Merchant" }] },
    { type: "payment.reference", conditional_transaction_id: "abc" },
  ],
  ...(cnf ? { cnf: { jwk: jwkOf(agentKey) } } : {}),
  iat: AP2_NOW - 100,
  exp: AP2_NOW + 3600,
});
const closedMandate = (amount: number, payee = "merchant_1") => ({
  vct: "mandate.payment.1",
  transaction_id: "tx-1",
  payee: { id: payee, name: payee === "merchant_1" ? "Demo Merchant" : "Evil Shop" },
  payment_amount: { amount, currency: "USD" },
  payment_instrument: { id: "card-1", type: "card", description: "Visa ending 4242" },
});

describe("AP2 v0.2 SD-JWT chain (fixture)", () => {
  it("splits hops, resolves disclosures and verifies the delegated signature + sd_hash", () => {
    const hops = parseChain(CHAIN)!;
    expect(hops).toHaveLength(2);
    expect(hops[0].resolved.delegate_payload).toHaveLength(1);
    const d = dec(CHAIN, AP2_NOW);
    expect(d.kind).toBe("ap2.mandate-chain");
    expect(d.summary).toBe(
      "AP2 payment mandate chain (2 hops): the user's open mandate allows max $200.00 USD per payment, only payee Demo Merchant (merchant_1), tied to checkout FzLoxb…7JN8, expires 28 Apr 2026, 03:12:37 UTC; the agent closed it to pay $199.00 USD to Demo Merchant (merchant_1) with Card •••4242, within those limits. Agent signature and sd_hash binding verify; the root issuer signature isn't checked (no key).",
    );
    expect(codes(d)).toEqual(expect.arrayContaining(["ROOT_SIG_UNCHECKED", "MANDATE_WITHIN_CONSTRAINTS"]));
    expect(d.flags.filter((f) => f.level === "danger" || f.level === "warn")).toEqual([]);
    const hop2 = d.sections.find((s) => s.title.startsWith("Hop 2"))!;
    expect(hop2.fields.find((f) => f.label === "Signature")?.value).toBe("valid (signed by hop 1's cnf key)");
    expect(hop2.fields.find((f) => f.label === "sd_hash")?.note).toContain("matches");
  });

  it("flags the mandate as expired against real time", () => {
    const d = decode(CHAIN);
    expect(flagOf(d, "MANDATE_EXPIRED")?.level).toBe("danger");
    expect(d.summary).toContain("the mandate has expired");
  });

  it("a substituted closed-mandate disclosure is not covered by the signature", () => {
    const [h1, h2] = CHAIN.split("~~");
    const parts = h2.split("~");
    const disc = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    disc[1].payment_amount.amount = 25000;
    parts[1] = bu(JSON.stringify(disc));
    const d = dec(`${h1}~~${parts.join("~")}`, AP2_NOW);
    expect(codes(d)).toEqual(expect.arrayContaining(["DISCLOSURE_UNUSED", "HOP_NO_MANDATE"]));
  });

  it("editing the open mandate breaks the next hop's sd_hash", () => {
    const [h1, h2] = CHAIN.split("~~");
    const parts = h1.split("~");
    const disc = JSON.parse(Buffer.from(parts[2], "base64url").toString());
    disc[1].constraints[0].max = 999999;
    parts[2] = bu(JSON.stringify(disc));
    const d = dec(`${parts.join("~")}~~${h2}`, AP2_NOW);
    expect(flagOf(d, "SD_HASH_MISMATCH")?.level).toBe("danger");
    expect(d.summary).toContain("FAILED");
  });

  it("checkout chain from the AP2 docs: merchant cart hash and line items check out", () => {
    const d = dec(readFixture("ap2-checkout-chain.txt"), AP2_NOW);
    expect(d.kind).toBe("ap2.mandate-chain");
    expect(codes(d)).toEqual(expect.arrayContaining(["CHECKOUT_HASH_OK", "MANDATE_WITHIN_CONSTRAINTS"]));
    expect(d.summary).toContain(
      "the agent closed it to buy 1 x Supershoe Limited Edition Gold Sneaker Womens 9 from Demo Merchant (merchant_1) for $199.00 USD, within those limits",
    );
  });
});

describe("AP2 v0.2 chains built in-test", () => {
  it("verifies a fresh chain end to end", () => {
    const d = dec(buildChain(openMandate(20000), closedMandate(15000)), AP2_NOW);
    expect(codes(d)).toContain("MANDATE_WITHIN_CONSTRAINTS");
    expect(d.flags.filter((f) => f.level === "danger")).toEqual([]);
  });

  it("closed mandate over the cap and to another payee is a violation", () => {
    const d = dec(buildChain(openMandate(10000), closedMandate(19900, "merchant_9")), AP2_NOW);
    const msgs = d.flags.filter((f) => f.code === "MANDATE_CONSTRAINT_VIOLATION").map((f) => f.message);
    expect(msgs).toEqual([
      "Hop 2 breaks hop 1's constraints: $199.00 USD exceeds the $100.00 USD cap.",
      "Hop 2 breaks hop 1's constraints: payee Evil Shop (merchant_9) is not in the allowed list.",
    ]);
    expect(d.summary).toContain("BREAKING those limits");
  });

  it("closed hop signed by a key other than the delegated cnf key", () => {
    const d = dec(buildChain(openMandate(20000), closedMandate(100), { closedSigner: new Uint8Array(32).fill(33) }), AP2_NOW);
    expect(flagOf(d, "HOP_SIG_INVALID")?.level).toBe("danger");
  });

  it("closed hop without sd_hash is unbound", () => {
    expect(codes(dec(buildChain(openMandate(20000), closedMandate(100), { skipSdHash: true }), AP2_NOW))).toContain("HOP_NO_SD_HASH");
  });

  it("open mandate without cnf: unbound on its own, and the next hop can't be verified", () => {
    expect(codes(dec(buildChain(openMandate(20000, false), null), AP2_NOW))).toContain("OPEN_MANDATE_UNBOUND");
    expect(codes(dec(buildChain(openMandate(20000, false), closedMandate(100)), AP2_NOW))).toContain("HOP_UNBOUND");
  });

  it("open mandate with no amount limit", () => {
    const m = {
      vct: "mandate.payment.open.1",
      constraints: [{ type: "payment.reference", conditional_transaction_id: "x" }],
      cnf: { jwk: jwkOf(agentKey) },
      exp: AP2_NOW + 60,
    };
    const d = dec(buildChain(m, null), AP2_NOW);
    expect(codes(d)).toEqual(expect.arrayContaining(["MANDATE_NO_AMOUNT_LIMIT", "MANDATE_ANY_PAYEE", "OPEN_MANDATE_PENDING"]));
  });
});

describe("AP2 x x402 credential bundle", () => {
  it("headline: the AP2 sample signs Base Sepolia USDC with 'USD Coin'", () => {
    const d = dec(readFixture("ap2-x402-bundle.json"), AP2_NOW);
    expect(d.kind).toBe("ap2.x402-credential");
    expect(d.summary).toBe(
      "AP2 x402 credential that authorizes 0xf39F…2266 to pay 199.00 USDC on Base Sepolia to 0x7099…79C8, valid until 28 Apr 2026. Signature will be rejected on-chain: signed with name 'USD Coin' but Base Sepolia USDC's domain name is 'USDC'. Its nonce binds it to the AP2 mandate chain.",
    );
    expect(flagOf(d, "EIP712_DOMAIN_MISMATCH")?.level).toBe("danger");
    expect(codes(d)).toEqual(expect.arrayContaining(["AP2_NONCE_BOUND", "AP2_KB_NONCE_OK", "AP2_AMOUNT_MATCHES", "AP2_PAYEE_UNBOUND"]));
    expect(d.kind === "ap2.x402-credential" && d.children?.[0].kind).toBe("ap2.mandate-chain");
  });

  it("same bundle signed with the correct domain verifies", async () => {
    const b = JSON.parse(readFixture("ap2-x402-bundle.json"));
    const acct = privateKeyToAccount(ANVIL_0);
    const a = b.eip_3009_payload.authorization;
    b.eip_3009_payload.signature = await acct.signTypedData({
      domain: { name: "USDC", version: "2", chainId: 84532, verifyingContract: USDC_BASE_SEPOLIA },
      types: TWA_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        from: a.from,
        to: a.to,
        value: BigInt(a.value),
        validAfter: 0n,
        validBefore: BigInt(a.validBefore),
        nonce: `0x${a.nonce}`,
      },
    });
    const d = dec(JSON.stringify(b), AP2_NOW);
    expect(codes(d)).toContain("SIG_VALID");
    expect(codes(d)).not.toContain("EIP712_DOMAIN_MISMATCH");
    expect(d.summary).toContain("Signature valid (as Base Sepolia USDC).");
  });

  it("nonce that isn't keccak256(chain) is unbound", () => {
    const b = JSON.parse(readFixture("ap2-x402-bundle.json"));
    b.payment_mandate_chain = buildChain(openMandate(20000), closedMandate(19900));
    const d = dec(JSON.stringify(b), AP2_NOW);
    expect(flagOf(d, "AP2_NONCE_UNBOUND")?.message).toContain("is not keccak256(payment_mandate_chain)");
    expect(keccak256(toHex(b.payment_mandate_chain))).not.toBe(`0x${b.eip_3009_payload.authorization.nonce}`);
  });
});

describe("AP2 v0.1 legacy mandates", () => {
  it("intent mandate without merchants or confirmation", () => {
    const d = dec(
      JSON.stringify({
        user_cart_confirmation_required: false,
        natural_language_description: "red running shoes under $120",
        merchants: null,
        skus: null,
        requires_refundability: false,
        intent_expiry: "2026-04-28T10:00:00Z",
      }),
      AP2_NOW,
    );
    expect(d.kind).toBe("ap2.v01.intent-mandate");
    expect(d.summary).toBe(
      'AP2 v0.1 intent: "red running shoes under $120", at any merchant, until 28 Apr 2026, 10:00:00 UTC, without cart confirmation.',
    );
    expect(codes(d)).toEqual(expect.arrayContaining(["INTENT_ANY_MERCHANT", "INTENT_NO_CART_CONFIRMATION"]));
  });

  it("intent mandate with no expiry", () => {
    expect(
      flagOf(
        dec(JSON.stringify({ natural_language_description: "anything", user_cart_confirmation_required: true }), AP2_NOW),
        "INTENT_NO_EXPIRY",
      )?.level,
    ).toBe("danger");
  });

  it("cart mandate with an embedded x402 PaymentRequired", () => {
    const req = JSON.parse(Buffer.from(FIX.x402_v2_http["PAYMENT-REQUIRED"][0], "base64").toString());
    const cart = {
      contents: {
        id: "cart_1",
        user_cart_confirmation_required: true,
        payment_request: {
          method_data: [{ supported_methods: "https://www.x402.org/", data: req }],
          details: {
            id: "order_1",
            display_items: [{ label: "Premium data", amount: { currency: "USD", value: 0.01 }, refund_period: 30 }],
            total: { label: "Total", amount: { currency: "USD", value: 0.01 } },
          },
        },
        cart_expiry: "2026-04-28T04:00:00Z",
        merchant_name: "Example API",
      },
      merchant_authorization: null,
    };
    const d = dec(JSON.stringify(cart), AP2_NOW);
    expect(d.kind).toBe("ap2.v01.cart-mandate");
    expect(d.summary).toBe(
      "AP2 v0.1 cart from Example API: Premium data for $0.01 USD, payable over x402, valid until 28 Apr 2026, 04:00:00 UTC.",
    );
    expect(codes(d)).toContain("CART_UNSIGNED");
    expect(d.kind === "ap2.v01.cart-mandate" && d.children?.[0].kind).toBe("x402.payment-required");
  });

  it("payment mandate without user authorization", () => {
    const pm = {
      payment_mandate_contents: {
        payment_mandate_id: "pm_1",
        payment_details_id: "order_1",
        payment_details_total: { label: "Total", amount: { currency: "USD", value: 120 } },
        payment_response: { request_id: "order_1", method_name: "CARD", details: { token: "tok_1" } },
        merchant_agent: "shoe-merchant",
        timestamp: "2026-04-28T03:00:00Z",
      },
    };
    const d = dec(JSON.stringify(pm), AP2_NOW);
    expect(d.summary).toBe("AP2 v0.1 payment of $120.00 USD via CARD to merchant agent shoe-merchant, with NO user authorization.");
    expect(flagOf(d, "PAYMENT_MANDATE_UNSIGNED")?.level).toBe("danger");
  });
});

describe("structured UI hints", () => {
  it("tags chain sections and fields with their hop and time fields with unix seconds", () => {
    const d = dec(CHAIN, AP2_NOW);
    const hopSections = d.sections.filter((s) => s.hop !== undefined);
    expect(hopSections.map((s) => [s.hop, s.title.slice(0, 5)])).toEqual([
      [1, "Hop 1"],
      [2, "Hop 2"],
    ]);
    const chainOverview = d.sections.find((s) => s.title === "Chain")!;
    expect(chainOverview.fields.filter((f) => f.hop !== undefined).map((f) => f.hop)).toEqual([1, 2]);
    const expires = hopSections[0].fields.find((f) => f.label === "Expires")!;
    expect(expires.kind).toBe("time");
    expect(expires.unixSeconds).toBe(1777345957);
  });
});
