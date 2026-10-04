// AP2 x x402 credential bundle {payment_mandate_chain, payment_nonce, eip_3009_payload}, as emitted
// by AP2's x402_credentials_provider_mcp sample, where EIP-3009 nonce = keccak256(mandate chain).
// Source: https://github.com/google-agentic-commerce/AP2/tree/main/code/samples/python/src/roles/x402_credentials_provider_mcp
import { decodeSdJwtChain } from "./chain.js";
import { merchantName } from "./mandates.js";
import { isRecord } from "../core/encoding.js";
import { asText, field, flag, formatMinor, section, short } from "../core/format.js";
import { make } from "../core/result.js";
import { keccakUtf8, sameAddress } from "../crypto/eip712.js";
import { analyzeEip3009 } from "../evm/eip3009.js";
import type { Decoded, Flag } from "../types.js";

type Obj = Record<string, unknown>;

// ---------------------------------------------------------------- AP2 x x402 bundle

export const isAp2X402Bundle = (o: Obj) => typeof o.payment_mandate_chain === "string" && isRecord(o.eip_3009_payload);

export function decodeAp2X402Bundle(o: Obj, now: number): Decoded {
  const chainStr = asText(o.payment_mandate_chain);
  const ep = o.eip_3009_payload as Obj;
  const auth = isRecord(ep.authorization) ? ep.authorization : {};
  const flags: Flag[] = [];
  const children: Decoded[] = [];
  const chain = decodeSdJwtChain(chainStr, now);
  if (chain) children.push(chain.decoded);
  else flags.push(flag("warn", "AP2_CHAIN_UNPARSEABLE", "payment_mandate_chain doesn't parse as an SD-JWT chain."));

  // 1. nonce binding
  const expectedNonce = keccakUtf8(chainStr).toLowerCase();
  const nonce = asText(auth.nonce, "")
    .toLowerCase()
    .replace(/^(?!0x)/, "0x");
  const bound = nonce === expectedNonce;
  flags.push(
    bound
      ? flag(
          "ok",
          "AP2_NONCE_BOUND",
          "EIP-3009 nonce equals keccak256(payment_mandate_chain), so this payment can only be the one the mandate chain authorized, and only once.",
        )
      : flag(
          "danger",
          "AP2_NONCE_UNBOUND",
          `EIP-3009 nonce ${short(nonce, 10, 6)} is not keccak256(payment_mandate_chain) (${short(expectedNonce, 10, 6)}). The payment isn't bound to this mandate chain; it could be reused with a different mandate.`,
        ),
  );
  // 2. KB nonce in terminal hop
  const last = chain?.hops[chain.hops.length - 1];
  if (last && o.payment_nonce !== undefined && last.jwt.payload.nonce !== undefined) {
    if (asText(last.jwt.payload.nonce) === asText(o.payment_nonce))
      flags.push(flag("ok", "AP2_KB_NONCE_OK", "payment_nonce matches the nonce the agent signed into the closed mandate."));
    else
      flags.push(
        flag(
          "danger",
          "AP2_KB_NONCE_MISMATCH",
          `payment_nonce '${asText(o.payment_nonce)}' differs from the closed mandate's signed nonce '${asText(last.jwt.payload.nonce)}'. The credential was issued for a different request.`,
        ),
      );
  }
  // 3. EIP-3009 analysis (network inferred from the signature domain)
  const analysis = analyzeEip3009({ signature: ep.signature, authorization: auth }, {}, now);
  flags.push(...analysis.flags);
  // 4. amount vs closed mandate
  const closed = chain?.closed;
  if (closed && isRecord(closed.payment_amount)) {
    const pa = closed.payment_amount;
    const cur = asText(pa.currency, "").toUpperCase();
    const tk = analysis.token;
    if (cur === "USD" && !tk) {
      flags.push(
        flag(
          "warn",
          "AP2_AMOUNT_UNCHECKED",
          `The closed mandate pays ${formatMinor(pa.amount, pa.currency)}, but the EIP-3009 token isn't one paydecode knows, so its decimals (and the on-chain amount) can't be compared.`,
        ),
      );
    } else if (cur === "USD" && tk) {
      try {
        // Mandate amounts are cents; scale to the token's own decimals (6 for USDC, 18 for MegaUSD).
        const scale = tk.decimals - 2;
        const cents = BigInt(asText(pa.amount));
        const expected = scale >= 0 ? cents * 10n ** BigInt(scale) : undefined;
        const v = BigInt(asText(auth.value, "0"));
        if (expected !== undefined && v === expected)
          flags.push(
            flag(
              "ok",
              "AP2_AMOUNT_MATCHES",
              `On-chain amount matches the closed mandate (${formatMinor(pa.amount, pa.currency)} as ${tk.decimals}-decimal ${tk.symbol}).`,
            ),
          );
        else
          flags.push(
            flag(
              "danger",
              "AP2_AMOUNT_MISMATCH",
              `The EIP-3009 value (${asText(auth.value)} units) doesn't equal the closed mandate's ${formatMinor(pa.amount, pa.currency)}${expected !== undefined ? ` (${expected} units of ${tk.decimals}-decimal ${tk.symbol})` : ""}.`,
            ),
          );
      } catch {
        flags.push(
          flag(
            "warn",
            "AP2_AMOUNT_UNCHECKED",
            `Couldn't compare amounts: the mandate amount '${asText(pa.amount)}' or EIP-3009 value '${asText(auth.value)}' is not an integer.`,
          ),
        );
      }
    }
    const instr = isRecord(closed.payment_instrument) ? closed.payment_instrument : {};
    if (typeof instr.payee_address === "string") {
      if (sameAddress(instr.payee_address, auth.to))
        flags.push(flag("ok", "AP2_PAYEE_MATCHES", "EIP-3009 recipient matches the mandate's payee_address."));
      else
        flags.push(
          flag(
            "danger",
            "AP2_PAYEE_MISMATCH",
            `EIP-3009 pays ${short(auth.to)} but the mandate's payee_address is ${short(instr.payee_address)}.`,
          ),
        );
    } else {
      flags.push(
        flag(
          "warn",
          "AP2_PAYEE_UNBOUND",
          `The closed mandate has no on-chain payee_address, so nothing ties the recipient ${short(auth.to)} to the mandate's payee ${merchantName(closed.payee)}. (The AP2 sample falls back to a default merchant wallet.)`,
        ),
      );
    }
  }
  const summary = `AP2 x402 credential that ${analysis.summary.replace(/^Authorizes/, "authorizes")} ${bound ? "Its nonce binds it to the AP2 mandate chain." : "Its nonce does NOT bind it to the mandate chain."}`;
  return make(
    "ap2.x402-credential",
    "AP2 x x402 payment credential",
    summary,
    [
      section("Binding", [
        field("Mandate chain hash (keccak256)", expectedNonce, "hash"),
        field("EIP-3009 nonce", nonce, "hash", bound ? "matches" : "does NOT match"),
        ...(o.payment_nonce !== undefined ? [field("payment_nonce", asText(o.payment_nonce), "code")] : []),
      ]),
      ...analysis.sections,
    ],
    flags,
    o,
    children,
  );
}
