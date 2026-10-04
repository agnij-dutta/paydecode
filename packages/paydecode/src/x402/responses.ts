// x402 SettleResponse, VerifyResponse, facilitator /verify and /settle bodies, and /supported.
import { isRecord } from "../core/encoding.js";
import { asText, field, flag, listJoin, plural, section, short } from "../core/format.js";
import { networkInfo } from "../core/networks.js";
import { make } from "../core/result.js";
import type { Decoded, Field, Flag } from "../types.js";
import { decodePaymentPayload } from "./payload.js";
import { describeRequirement, extensionsSection } from "./requirements.js";
import { explainError } from "./shapes.js";

type Obj = Record<string, unknown>;

export const PLACEHOLDER_TX = /^0x(1234567890abcdef){4}$/i;

export function decodeSettleResponse(o: Obj): Decoded {
  const net = o.network !== undefined ? networkInfo(o.network) : undefined;
  const flags: Flag[] = [];
  const tx = asText(o.transaction, "");
  const payer = typeof o.payer === "string" ? o.payer : undefined;
  let summary: string;
  if (o.success) {
    summary = `Settlement succeeded${net ? ` on ${net.name}` : ""}${tx ? `: transaction ${short(tx, 10, 6)}` : ""}${payer ? `, paid by ${short(payer)}` : ""}${o.amount !== undefined ? ` (charged ${asText(o.amount)} atomic units)` : ""}.`;
    flags.push(flag("ok", "SETTLED", "The facilitator reports the payment landed on-chain."));
    if (!tx)
      flags.push(
        flag("warn", "NO_TX_HASH", "Marked successful but no transaction hash was returned, so there's nothing to look up on-chain."),
      );
  } else {
    summary = `Settlement failed${net ? ` on ${net.name}` : ""}: ${explainError(o.errorReason ?? "no reason given")}.${typeof o.errorMessage === "string" ? ` "${o.errorMessage}"` : ""}${payer ? ` Payer ${short(payer)}.` : ""}`;
    flags.push(flag("danger", "SETTLE_FAILED", `Settlement failed: ${explainError(o.errorReason ?? "unknown")}. No money moved.`));
  }
  if (PLACEHOLDER_TX.test(tx))
    flags.push(
      flag(
        "info",
        "PLACEHOLDER_TX",
        "The transaction hash looks like a documentation placeholder (0x1234567890abcdef...), not a real transaction.",
      ),
    );
  const fields: Field[] = [
    field("Success", asText(o.success)),
    ...(o.errorReason ? [field("Error reason", explainError(o.errorReason))] : []),
    ...(o.errorMessage ? [field("Error message", asText(o.errorMessage))] : []),
    ...(tx ? [field("Transaction", tx, "hash")] : []),
    ...(net ? [field("Network", net.name, "text", net.caip2 ?? asText(o.network))] : []),
    ...(payer ? [field("Payer", payer, "address")] : []),
    ...(o.amount !== undefined ? [field("Amount charged", asText(o.amount), "amount")] : []),
  ];
  return make(
    "x402.settle-response",
    "x402 settlement response",
    summary,
    [section("Settlement", fields), ...extensionsSection(o.extensions)],
    flags,
    o,
  );
}

export function decodeVerifyResponse(o: Obj): Decoded {
  const payer = typeof o.payer === "string" ? o.payer : undefined;
  const ok = o.isValid === true;
  const summary = ok
    ? `Facilitator says the payment is valid${payer ? ` (payer ${short(payer)})` : ""} and can be settled.`
    : `Facilitator rejected the payment: ${explainError(o.invalidReason ?? "no reason given")}.${typeof o.invalidMessage === "string" ? ` "${o.invalidMessage}"` : ""}`;
  return make(
    "x402.verify-response",
    "x402 verify response",
    summary,
    [
      section("Verification", [
        field("Valid", asText(o.isValid)),
        ...(o.invalidReason ? [field("Reason", explainError(o.invalidReason))] : []),
        ...(o.invalidMessage ? [field("Message", asText(o.invalidMessage))] : []),
        ...(payer ? [field("Payer", payer, "address")] : []),
      ]),
    ],
    [
      ok
        ? flag("ok", "VERIFIED", "Facilitator verification passed.")
        : flag("danger", "VERIFY_FAILED", `Verification failed: ${explainError(o.invalidReason ?? "unknown")}.`),
    ],
    o,
  );
}

export function decodeFacilitatorRequest(o: Obj, now: number, endpoint?: string): Decoded {
  const pp = o.paymentPayload as Obj;
  const req = isRecord(o.paymentRequirements) ? o.paymentRequirements : undefined;
  const child = decodePaymentPayload(pp, now, req);
  const reqView = req ? describeRequirement(req, Number(pp.x402Version ?? o.x402Version ?? 2)) : undefined;
  const summary = `Facilitator ${endpoint ? `/${endpoint} ` : ""}request: ${child.summary}`;
  return make(
    "x402.facilitator-request",
    `x402 facilitator ${endpoint ? `/${endpoint}` : "/verify or /settle"} request`,
    summary,
    [...(reqView ? [section("Payment requirements", reqView.fields)] : []), ...child.sections],
    [...child.flags, ...(reqView?.flags ?? [])],
    o,
    [],
  );
}

export function decodeSupported(o: Obj): Decoded {
  const kinds = (o.kinds as Obj[]).filter(isRecord);
  const byScheme = new Map<string, Set<string>>();
  for (const k of kinds) {
    const s = `${asText(k.scheme)} (v${asText(k.x402Version, "?")})`;
    if (!byScheme.has(s)) byScheme.set(s, new Set());
    byScheme.get(s)!.add(networkInfo(k.network).name);
  }
  const parts = [...byScheme.entries()].map(([s, nets]) => `${s} on ${listJoin([...nets])}`);
  const signers = isRecord(o.signers) ? o.signers : {};
  const fields = kinds.map((k) =>
    field(
      `${asText(k.scheme)} v${asText(k.x402Version, "?")}`,
      networkInfo(k.network).name,
      "text",
      `${asText(k.network)}${isRecord(k.extra) ? ` extra ${JSON.stringify(k.extra)}` : ""}`,
    ),
  );
  return make(
    "x402.supported",
    "x402 facilitator /supported",
    `Facilitator supports ${plural(kinds.length, "scheme/network pair")}: ${parts.join("; ")}.`,
    [
      section("Supported kinds", fields),
      ...(Object.keys(signers).length
        ? [
            section(
              "Signers",
              Object.entries(signers).flatMap(([k, v]) =>
                Array.isArray(v) ? v.map((addr) => field(k, asText(addr), "address")) : [field(k, JSON.stringify(v), "code")],
              ),
            ),
          ]
        : []),
      ...(Array.isArray(o.extensions) && o.extensions.length
        ? [section("Extensions", [field("Extensions", (o.extensions as unknown[]).map(String).join(", "))])]
        : []),
    ],
    [],
    o,
  );
}

export function decodeRequirement(o: Obj): Decoded {
  const v = describeRequirement(o, o.amount !== undefined ? 2 : 1);
  return make(
    "x402.payment-requirements",
    "x402 payment requirements",
    `Requirement to pay ${v.text}.`,
    [section("Requirement", v.fields)],
    v.flags,
    o,
  );
}
