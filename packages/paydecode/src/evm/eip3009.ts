// x402 exact/EVM with assetTransferMethod "eip3009": TransferWithAuthorization payloads.
// Spec: https://github.com/x402-foundation/x402/tree/main/specs/schemes/exact
import { isRecord } from "../core/encoding.js";
import { asText, duration, field, flag, formatDay, relative, section, short, timeField, toUnix } from "../core/format.js";
import { chainName, findEvmToken, networkInfo } from "../core/networks.js";
import { isEvmAddress, sameAddress } from "../crypto/eip712.js";
import { amountFlags, amountText, assetFlags, windowFlags } from "./context.js";
import type { Analysis, PaymentContext } from "./context.js";
import { verifyEip3009Signature } from "./domain.js";
import type { Field, Flag } from "../types.js";

export function analyzeEip3009(payload: Record<string, unknown>, ctx: PaymentContext, now: number): Analysis {
  const auth = isRecord(payload.authorization) ? payload.authorization : {};
  const signature = asText(payload.signature, "");
  const net = ctx.network ? networkInfo(ctx.network) : undefined;
  const chainId = net?.chainId;
  const tk = findEvmToken(chainId, ctx.asset);
  const flags: Flag[] = [];

  const after = toUnix(auth.validAfter);
  const before = toUnix(auth.validBefore);
  const from = asText(auth.from, "");
  const to = asText(auth.to, "");

  const sig = verifyEip3009Signature(auth, signature, ctx);
  // If we inferred the token from the signature (no network in the artifact), use it for display.
  const inferred =
    !tk && !ctx.asset && sig.hit?.token && (chainId === undefined || sig.hit.token.chainId === chainId) ? sig.hit.token : undefined;
  const shownTk = tk ?? inferred;
  const shownNet = net?.name ?? (shownTk ? `${chainName(shownTk.chainId)} (inferred from signature)` : undefined);
  if (inferred) {
    flags.push(
      flag(
        "info",
        "ASSET_INFERRED",
        `The artifact doesn't name the token; the signature's EIP-712 domain identifies it as ${chainName(inferred.chainId)} ${inferred.symbol} (${short(inferred.address)}).`,
      ),
    );
  }
  const amt = amountText(auth.value, shownTk, ctx.asset);

  flags.push(...sig.flags);
  flags.push(...windowFlags(after, before, now, ctx));
  flags.push(...amountFlags(auth.value, ctx, shownTk));
  flags.push(...assetFlags(ctx, tk, chainId));
  if (ctx.payTo && isEvmAddress(ctx.payTo) && isEvmAddress(to)) {
    if (!sameAddress(ctx.payTo, to)) {
      flags.push(
        flag(
          "danger",
          "PAYTO_MISMATCH",
          `Pays ${short(to)} but the requirements say payTo is ${short(ctx.payTo)}. Money would go to the wrong address; the server should refuse it.`,
        ),
      );
    } else flags.push(flag("ok", "PAYTO_MATCHES", `Recipient matches the requirements' payTo (${short(to)}).`));
  }
  if (isEvmAddress(from) && sameAddress(from, to))
    flags.push(flag("warn", "SELF_PAYMENT", "from and to are the same address: this pays itself."));
  if (typeof auth.nonce === "string" && !/^(0x)?[0-9a-fA-F]{64}$/.test(auth.nonce)) {
    flags.push(flag("warn", "NONCE_FORMAT", `Nonce '${short(auth.nonce, 10, 4)}' is not 32 bytes of hex; EIP-3009 nonces are bytes32.`));
  }

  const fields: Field[] = [
    field("Payer (from)", from, "address"),
    field("Recipient (to)", to, "address"),
    field("Amount", amt, "amount", `raw value ${asText(auth.value)}`),
    field("Network", shownNet ?? "not stated", "text", net?.caip2),
    ...(ctx.asset ? [field("Asset", ctx.asset, "address", tk ? `${tk.symbol}, ${tk.decimals} decimals` : "unknown token")] : []),
    timeField("Valid after", after, now, auth.validAfter),
    timeField("Valid before", before, now, auth.validBefore),
    ...(after !== undefined && before !== undefined
      ? [
          field(
            "Window",
            duration(before - (after > 0 ? after : now)),
            "text",
            after > 0 ? undefined : "measured from now, since validAfter is 0",
          ),
        ]
      : []),
    field("Nonce", asText(auth.nonce, ""), "hash"),
  ];

  let when: string;
  if (after !== undefined && before !== undefined && after > 0) when = `valid for ${duration(before - after)} starting ${formatDay(after)}`;
  else if (before !== undefined) when = `valid until ${formatDay(before)}`;
  else when = "with no stated validity window";
  const state =
    before !== undefined && before <= now
      ? ` (expired ${relative(before, now)})`
      : after !== undefined && after > now
        ? ` (not valid until ${relative(after, now)})`
        : "";
  const summary = `Authorizes ${short(from)} to pay ${amt}${shownNet ? ` on ${shownNet.replace(" (inferred from signature)", "")}` : ""} to ${short(to)}, ${when}${state}. ${sig.phrase}`;

  return {
    sections: [
      section("EIP-3009 transfer authorization", fields),
      section("Signature", [field("Signature", signature, "code"), ...sig.fields]),
    ],
    flags,
    summary,
    sigPhrase: sig.phrase,
    payer: from,
  };
}

/** Decode + verify an exact/upto EVM Permit2 payload. */
