// Edge cases found in review: hostile input, contract-exact time windows, per-asset decimals,
// forged-vs-misdomained signatures, and the fast recovery path agreeing with full recovery.
import { describe, it, expect } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { decode, detect, parseSdToken, MAX_INPUT_LENGTH } from "../src/index.js";
import { formatMinor, currencyDecimals, toUnixSeconds, relative } from "../src/core/format.js";
import { jsonTooDeep } from "../src/core/encoding.js";
import { parseAuthParams } from "../src/mpp.js";
import { FIX, X402_NOW, b64, unb64, codes, flagOf, dec, USDC_BASE_SEPOLIA, ANVIL_0, TWA_TYPES } from "./helpers.js";

const V2_SIG: string = FIX.x402_v2_http["PAYMENT-SIGNATURE"][0];
const VALID_AFTER = 1740672089;
const VALID_BEFORE = 1740672154;
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const bu = (s: string) => Buffer.from(s).toString("base64url");

/** EIP-3009 payload whose `from` is ANVIL_0, signed by `signerKey` under domain `signName`, with `extra.name = extraName`. */
async function eip3009(opts: { signName: string; extraName: string; signerKey?: `0x${string}`; value?: bigint }) {
  const claimed = privateKeyToAccount(ANVIL_0);
  const signer = privateKeyToAccount(opts.signerKey ?? ANVIL_0);
  const auth = {
    from: claimed.address,
    to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C" as `0x${string}`,
    value: opts.value ?? 10000n,
    validAfter: BigInt(VALID_AFTER),
    validBefore: BigInt(VALID_BEFORE),
    nonce: `0x${"22".repeat(32)}` as const,
  };
  const signature = await signer.signTypedData({
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
      payTo: auth.to,
      maxTimeoutSeconds: 60,
      extra: { name: opts.extraName, version: "2" },
    },
    payload: {
      signature,
      authorization: { ...auth, value: String(auth.value), validAfter: String(VALID_AFTER), validBefore: String(VALID_BEFORE) },
    },
  };
}

describe("hostile input never throws or hangs", () => {
  const deep = (n: number) => '{"a":'.repeat(n) + "1" + "}".repeat(n);

  it("deeply nested JSON (raw, base64, inside a JWT) is refused with an explanation", () => {
    for (const input of [deep(100_000), "[".repeat(100_000) + "]".repeat(100_000), Buffer.from(deep(50_000)).toString("base64")]) {
      const d = decode(input, { now: X402_NOW });
      expect(d.kind).toBe("unknown");
      expect(codes(d)).toContain("JSON_TOO_DEEP");
      expect(codes(d)).not.toContain("DECODER_ERROR");
    }
    const jwt = `eyJhbGciOiJFUzI1NiJ9.${bu(deep(50_000))}.AAAA~`;
    expect(() => decode(jwt)).not.toThrow();
    expect(() => detect(deep(100_000))).not.toThrow();
  });

  it("nesting up to the limit still parses", () => {
    expect(jsonTooDeep("[".repeat(64) + "]".repeat(64))).toBe(false);
    expect(jsonTooDeep("[".repeat(65) + "]".repeat(65))).toBe(true);
    // brackets inside strings don't count
    expect(jsonTooDeep(JSON.stringify({ s: "[".repeat(500) }))).toBe(false);
  });

  it("oversized input is refused up front", () => {
    const big = Buffer.alloc(MAX_INPUT_LENGTH, 7).toString("base64");
    const t = performance.now();
    const d = decode(big);
    expect(performance.now() - t).toBeLessThan(200);
    expect(d.title).toBe("Input too large");
    expect(codes(d)).toEqual(["INPUT_TOO_LARGE"]);
    expect(detect(big).kind).toBe("unknown");
  });

  it("__proto__ keys stay plain data and don't change what the decoder sees", () => {
    const payload = JSON.parse('{"__proto__":{"cnf":{"jwk":{"kty":"EC"}},"delegate_payload":[{"vct":"mandate.payment.1"}]},"a":1}');
    const tok = parseSdToken(`eyJhbGciOiJFUzI1NiJ9.${bu(JSON.stringify(payload))}.AAAA~`)!;
    expect(Object.getPrototypeOf(tok.resolved)).toBe(Object.prototype);
    expect(tok.resolved.cnf).toBeUndefined();
    expect(tok.resolved.delegate_payload).toBeUndefined();
    expect(Object.keys(tok.resolved)).toEqual(["__proto__", "a"]);

    const params = parseAuthParams('__proto__="x", id="abc"');
    expect(Object.getPrototypeOf(params)).toBe(Object.prototype);
    expect(params.id).toBe("abc");
    expect(({} as Record<string, unknown>).cnf).toBeUndefined();
  });

  it("non-UTF-8 bytes and lone surrogates decode without throwing", () => {
    const bad = Buffer.from([0xff, 0xfe, 0x7b, 0x22, 0xc3, 0x28, 0x22, 0x3a, 0x31, 0x7d]).toString("base64");
    expect(decode(bad).kind).toBe("unknown");
    expect(() => decode('{"x402Version":1,"scheme":"exact","network":"base","payload":{"signature":"\\ud800"}}')).not.toThrow();
  });

  it("an authorization value that overflows uint256 is malformed, not checked", () => {
    const p = unb64(V2_SIG);
    p.payload.authorization.validBefore = "9".repeat(400);
    const d = dec(b64(p), X402_NOW);
    expect(flagOf(d, "AUTH_FIELD_INVALID")?.message).toContain("does not fit in a uint256");
    expect(codes(d)).not.toContain("SIG_VALID");
  });

  it("non-finite times read as far future instead of 'Infinity years'", () => {
    expect(relative(Infinity, 0)).toBe("in the far future");
  });
});

describe("EIP-3009 window matches FiatToken: now > validAfter && now < validBefore", () => {
  it("expires at exactly validBefore", () => {
    expect(codes(dec(V2_SIG, VALID_BEFORE - 1))).not.toContain("AUTH_EXPIRED");
    expect(codes(dec(V2_SIG, VALID_BEFORE))).toContain("AUTH_EXPIRED");
  });

  it("is not yet valid at exactly validAfter", () => {
    expect(codes(dec(V2_SIG, VALID_AFTER))).toContain("AUTH_NOT_YET_VALID");
    expect(codes(dec(V2_SIG, VALID_AFTER + 1))).not.toContain("AUTH_NOT_YET_VALID");
  });

  it("on-chain timestamps are seconds, never reinterpreted as milliseconds", () => {
    // 1.5e12 seconds is ~47,500 years out. The old heuristic read it as ms (2017) and called it expired.
    const p = unb64(V2_SIG);
    p.payload.authorization.validBefore = "1500000000000";
    const d = dec(b64(p), X402_NOW);
    expect(codes(d)).not.toContain("AUTH_EXPIRED");
    expect(codes(d)).toContain("AUTH_WINDOW_HUGE");
    expect(toUnixSeconds("1500000000000")).toBe(1500000000000);
    expect(toUnixSeconds("12.5")).toBeUndefined();
  });
});

describe("amounts use each asset's real decimals", () => {
  it("ISO 4217 minor units: 0, 2 and 3 decimal currencies", () => {
    expect(formatMinor(500, "JPY")).toBe("¥500 JPY");
    expect(formatMinor(1234, "KWD")).toBe("1.234 KWD");
    expect(formatMinor(1999, "usd")).toBe("$19.99 USD");
    expect(currencyDecimals("BHD")).toBe(3);
  });

  it("a token symbol is not a currency: no guessed cents", () => {
    expect(formatMinor(1000000, "USDC")).toBe("1000000 minor units of USDC");
    expect(formatMinor(5, undefined)).toBe("5 minor units (currency not stated)");
    expect(currencyDecimals("USDC")).toBeUndefined();
  });

  it("an 18-decimal x402 default asset is priced with 18 decimals", () => {
    const req = {
      x402Version: 2,
      accepts: [
        {
          scheme: "exact",
          network: "eip155:4326",
          amount: "1500000000000000000",
          asset: "0xFAfDdbb3FC7688494971a79cc65DCa3EF82079E7",
          payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
          maxTimeoutSeconds: 60,
          extra: { assetTransferMethod: "permit2" },
        },
      ],
    };
    expect(dec(b64(req), X402_NOW).summary).toContain("1.50 MegaUSD on MegaETH");
  });

  it("an unknown asset is shown in atomic units, never as 6-decimal USDC", () => {
    const p = unb64(V2_SIG);
    p.accepted.asset = "0x1111111111111111111111111111111111111111";
    const d = dec(b64(p), X402_NOW);
    expect(d.summary).toContain("10000 atomic units of 0x1111…1111");
    expect(d.summary).not.toContain("0.01");
    expect(codes(d)).toContain("UNKNOWN_ASSET");
  });
});

describe("domain diagnosis never blames the domain for a forged signature", () => {
  const attacker = generatePrivateKey();

  it("forged under the token's real domain: invalid, no domain mismatch", async () => {
    const d = dec(b64(await eip3009({ signName: "USDC", extraName: "USDC", signerKey: attacker })), X402_NOW);
    expect(flagOf(d, "SIG_INVALID")?.message).toContain("Base Sepolia USDC's on-chain domain");
    expect(codes(d)).not.toContain("EIP712_DOMAIN_MISMATCH");
    expect(codes(d)).not.toContain("SIG_VALID");
  });

  it("forged under the wrong domain the requirements advertise: still just invalid", async () => {
    const d = dec(b64(await eip3009({ signName: "USD Coin", extraName: "USD Coin", signerKey: attacker })), X402_NOW);
    expect(codes(d)).toContain("SIG_INVALID");
    expect(codes(d)).not.toContain("EIP712_DOMAIN_MISMATCH");
    expect(codes(d)).not.toContain("SIG_VALID");
    expect(d.summary).toContain("Signature INVALID.");
  });

  it("genuine wrong-domain signature over a tampered value: invalid, not a domain problem", async () => {
    const p = await eip3009({ signName: "USD Coin", extraName: "USD Coin" });
    p.payload.authorization.value = "20000";
    const d = dec(b64(p), X402_NOW);
    expect(codes(d)).toContain("SIG_INVALID");
    expect(codes(d)).not.toContain("EIP712_DOMAIN_MISMATCH");
  });

  it("forged with no network context: invalid, never valid", async () => {
    const p = await eip3009({ signName: "USDC", extraName: "USDC", signerKey: attacker });
    const v1 = { x402Version: 1, scheme: "exact", network: "base-sepolia", payload: p.payload };
    const bare = { x402Version: 1, scheme: "exact", payload: p.payload };
    for (const o of [v1, bare]) {
      const d = dec(b64(o), X402_NOW);
      expect(codes(d)).toContain("SIG_INVALID");
      expect(codes(d)).not.toContain("SIG_VALID");
      expect(codes(d)).not.toContain("EIP712_DOMAIN_MISMATCH");
    }
  });

  it("the genuine wrong-domain signature is still diagnosed as a domain mismatch", async () => {
    const d = dec(b64(await eip3009({ signName: "USD Coin", extraName: "USD Coin" })), X402_NOW);
    expect(flagOf(d, "EIP712_DOMAIN_MISMATCH")?.level).toBe("danger");
    expect(codes(d)).not.toContain("SIG_INVALID");
  });

  it("a high-s (malleated) signature recovers, but is flagged because USDC rejects it", async () => {
    const p = await eip3009({ signName: "USDC", extraName: "USDC" });
    const sig: string = p.payload.signature;
    const s = BigInt("0x" + sig.slice(66, 130));
    const v = parseInt(sig.slice(130), 16);
    p.payload.signature = `0x${sig.slice(2, 66)}${(SECP256K1_N - s).toString(16).padStart(64, "0")}${v === 27 ? "1c" : "1b"}`;
    const d = dec(b64(p), X402_NOW);
    expect(codes(d)).toContain("SIG_VALID");
    expect(flagOf(d, "SIG_HIGH_S")?.level).toBe("warn");
    expect(codes(dec(b64(await eip3009({ signName: "USDC", extraName: "USDC" })), X402_NOW))).not.toContain("SIG_HIGH_S");
  });
});
