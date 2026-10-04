// x402 exact/upto EVM with assetTransferMethod "permit2": PermitWitnessTransferFrom payloads
// spent through the x402 Permit2 proxy (0x4020...0001 exact, 0x4020...0002 upto).
// Spec: https://github.com/x402-foundation/x402/tree/main/specs/schemes/exact
import { isRecord } from "../core/encoding.js";
import { asText, field, flag, formatDay, relative, section, short, timeField, toUnixSeconds } from "../core/format.js";
import {
  EVM_TOKENS,
  PERMIT2_ADDRESS,
  X402_EXACT_PERMIT2_PROXY,
  X402_UPTO_PERMIT2_PROXY,
  chainName,
  findEvmToken,
  networkInfo,
} from "../core/networks.js";
import { checksumAddress, isEvmAddress, recoverAddress, sameAddress, typedDataHash } from "../crypto/eip712.js";
import type { Domain, TypeMap } from "../crypto/eip712.js";
import { PERMIT2_WINDOW, amountFlags, amountText, assetFlags, hex0x, isExpired, windowFlags } from "./context.js";
import type { Analysis, PaymentContext } from "./context.js";
import type { Field, Flag } from "../types.js";

export const PERMIT2_EXACT_TYPES: TypeMap = {
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
};

export const PERMIT2_UPTO_TYPES: TypeMap = {
  ...PERMIT2_EXACT_TYPES,
  Witness: [
    { name: "to", type: "address" },
    { name: "facilitator", type: "address" },
    { name: "validAfter", type: "uint256" },
  ],
};

export function analyzePermit2(payload: Record<string, unknown>, ctx: PaymentContext, now: number): Analysis {
  const p = isRecord(payload.permit2Authorization) ? payload.permit2Authorization : {};
  const permitted = isRecord(p.permitted) ? p.permitted : {};
  const witness = isRecord(p.witness) ? p.witness : {};
  const signature = hex0x(payload.signature);
  const net = ctx.network ? networkInfo(ctx.network) : undefined;
  const chainId = net?.chainId;
  const token = asText(permitted.token, ctx.asset ?? "");
  const tk = findEvmToken(chainId, token);
  const from = asText(p.from, "");
  const to = asText(witness.to, "");
  const deadline = toUnixSeconds(p.deadline);
  const validAfter = toUnixSeconds(witness.validAfter);
  const isUpto = "facilitator" in witness || ctx.scheme === "upto";
  const expectedSpender = isUpto ? X402_UPTO_PERMIT2_PROXY : X402_EXACT_PERMIT2_PROXY;
  const amt = amountText(permitted.amount, tk, token);
  const flags: Flag[] = [];
  const types = isUpto ? PERMIT2_UPTO_TYPES : PERMIT2_EXACT_TYPES;
  const message = { permitted, spender: p.spender, nonce: p.nonce, deadline: p.deadline, witness };

  // Spender check: the whole security model of x402 Permit2 rests on it.
  if (!isEvmAddress(p.spender)) {
    flags.push(flag("danger", "PERMIT2_SPENDER_MISSING", "No valid spender in the Permit2 authorization."));
  } else if (!sameAddress(p.spender, expectedSpender)) {
    const other = sameAddress(p.spender, isUpto ? X402_EXACT_PERMIT2_PROXY : X402_UPTO_PERMIT2_PROXY);
    flags.push(
      flag(
        "danger",
        "PERMIT2_SPENDER_NOT_PROXY",
        other
          ? `Spender is the x402 ${isUpto ? "exact" : "upto"} proxy, but this is ${isUpto ? "an upto" : "an exact"} payment. Settlement will fail.`
          : `Spender is ${short(p.spender)}, not the x402 Permit2 proxy (${short(expectedSpender)}). Permit2 lets the spender move these tokens anywhere, so this signature hands ${amt} to an arbitrary contract instead of enforcing the witness recipient.`,
      ),
    );
  } else
    flags.push(
      flag(
        "ok",
        "PERMIT2_SPENDER_OK",
        `Spender is the canonical x402 ${isUpto ? "upto" : "exact"} Permit2 proxy, which enforces the witness recipient.`,
      ),
    );

  // Signature
  let sigPhrase = "Signature INVALID.";
  const sigFields: Field[] = [field("Signature", signature, "code")];
  if (chainId === undefined) {
    flags.push(flag("info", "SIG_NOT_CHECKED", "Network not stated, so the Permit2 signature (which commits to chainId) wasn't checked."));
    sigPhrase = "Signature not checked (no network).";
  } else {
    const dom = (cid: number): Domain => ({ name: "Permit2", chainId: cid, verifyingContract: PERMIT2_ADDRESS });
    let rec: string | null;
    try {
      rec = recoverAddress(typedDataHash(dom(chainId), types, "PermitWitnessTransferFrom", message), signature);
    } catch {
      rec = null;
    }
    if (rec && sameAddress(rec, from)) {
      flags.push(flag("ok", "SIG_VALID", `Signature valid: recovers to ${short(from)} under the Permit2 domain on ${net!.name}.`));
      sigPhrase = "Signature valid.";
      sigFields.push(field("Recovered signer", checksumAddress(from), "address", "matches from"));
    } else {
      const chains = [...new Set(EVM_TOKENS.map((x) => x.chainId))].filter((c) => c !== chainId);
      let other: number | undefined;
      for (const c of chains) {
        try {
          const r = recoverAddress(typedDataHash(dom(c), types, "PermitWitnessTransferFrom", message), signature);
          if (r && sameAddress(r, from)) {
            other = c;
            break;
          }
        } catch {
          /* skip */
        }
      }
      if (other !== undefined) {
        flags.push(
          flag(
            "danger",
            "SIG_WRONG_CHAIN",
            `Permit2 signature was made for ${chainName(other)} (chainId ${other}), not ${net!.name}. It will not verify here.`,
          ),
        );
        sigPhrase = `Signature is for ${chainName(other)}, not ${net!.name}.`;
      } else {
        flags.push(
          flag(
            "danger",
            "SIG_INVALID",
            `Signature does not match 'from'. It recovers to ${rec ? short(rec) : "nothing"}, not ${short(from)}. The permit fields were changed after signing, or a different key signed it.`,
          ),
        );
      }
      if (rec) sigFields.push(field("Recovered signer", rec, "address", `does NOT match from ${short(from)}`));
    }
  }

  // Window + amounts + recipient
  flags.push(...windowFlags(validAfter, deadline, now, ctx, PERMIT2_WINDOW));
  flags.push(...amountFlags(permitted.amount, ctx, tk));
  flags.push(...assetFlags({ ...ctx, asset: token }, tk, chainId));
  if (ctx.asset && token && !sameAddress(ctx.asset, token)) {
    flags.push(flag("danger", "PERMIT2_TOKEN_MISMATCH", `Permits token ${short(token)} but the requirements ask for ${short(ctx.asset)}.`));
  }
  if (ctx.payTo && isEvmAddress(ctx.payTo) && isEvmAddress(to)) {
    if (!sameAddress(ctx.payTo, to))
      flags.push(
        flag("danger", "PAYTO_MISMATCH", `Witness recipient is ${short(to)} but the requirements say payTo is ${short(ctx.payTo)}.`),
      );
    else flags.push(flag("ok", "PAYTO_MATCHES", `Witness recipient matches payTo (${short(to)}).`));
  }
  flags.push(
    flag(
      "info",
      "PERMIT2_APPROVAL_NEEDED",
      `Permit2 only works if ${short(from)} has approved the Permit2 contract for this token (or the payload carries an eip2612GasSponsoring / erc20ApprovalGasSponsoring extension).`,
    ),
  );

  const fields: Field[] = [
    field("Payer (from)", from, "address"),
    field("Recipient (witness.to)", to, "address"),
    ...(isUpto ? [field("Facilitator (witness.facilitator)", asText(witness.facilitator, ""), "address")] : []),
    field(isUpto ? "Maximum amount" : "Amount", amt, "amount", `raw ${asText(permitted.amount)}`),
    field("Token", token, "address", tk ? `${tk.symbol}, ${tk.decimals} decimals` : "unknown token"),
    field(
      "Spender",
      asText(p.spender, ""),
      "address",
      sameAddress(p.spender, expectedSpender) ? "x402 Permit2 proxy" : "NOT the x402 proxy",
    ),
    field("Network", net?.name ?? "not stated", "text", net?.caip2),
    timeField("Valid after (witness)", validAfter, now, witness.validAfter),
    timeField("Deadline", deadline, now, p.deadline),
    field("Permit2 nonce", asText(p.nonce, ""), "code"),
  ];
  const state = isExpired(deadline, now, PERMIT2_WINDOW) ? ` (expired ${relative(deadline!, now)})` : "";
  const summary = `Permit2 authorization for ${short(from)} to pay ${isUpto ? "up to " : ""}${amt}${net ? ` on ${net.name}` : ""} to ${short(to)} through ${sameAddress(p.spender, expectedSpender) ? "the x402 proxy" : `spender ${short(p.spender)}`}, valid until ${deadline !== undefined ? formatDay(deadline) : "an unstated deadline"}${state}. ${sigPhrase}`;
  return {
    sections: [section(`Permit2 PermitWitnessTransferFrom${isUpto ? " (upto)" : ""}`, fields), section("Signature", sigFields)],
    flags,
    summary,
    sigPhrase,
    payer: from,
  };
}
