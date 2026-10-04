// ACP (Agentic Commerce Protocol) delegated payments: delegate payment request, allowance,
// vault token and checkout payment data.
// Spec: https://github.com/agentic-commerce-protocol/agentic-commerce-protocol (Delegate Payment API).
import { isRecord } from "./core/encoding.js";
import { asText, duration, field, flag, formatMinor, formatTime, relative, section, short, timeField, toUnix } from "./core/format.js";
import { make } from "./core/result.js";
import type { Decoded, Field, Flag } from "./types.js";

type Obj = Record<string, unknown>;

// ---------------------------------------------------------------- ACP

export const isAcpDelegatePayment = (o: Obj) => isRecord(o.allowance) && ("payment_method" in o || "risk_signals" in o);
export const isAcpAllowance = (o: Obj) => typeof o.max_amount === "number" && "checkout_session_id" in o && "merchant_id" in o;
export const isAcpVaultToken = (o: Obj) => typeof o.id === "string" && /^vt_/.test(o.id) && "created" in o;
export const isAcpPaymentData = (o: Obj) => typeof o.handler_id === "string" && isRecord(o.instrument);

export function allowanceView(a: Obj, now: number): { text: string; fields: Field[]; flags: Flag[] } {
  const flags: Flag[] = [];
  const exp = toUnix(a.expires_at);
  const amt = formatMinor(a.max_amount, a.currency);
  if (exp !== undefined && exp <= now)
    flags.push(
      flag("danger", "ACP_ALLOWANCE_EXPIRED", `Allowance expired ${relative(exp, now)}; the vault token can no longer be charged.`),
    );
  if (exp === undefined)
    flags.push(flag("danger", "ACP_NO_EXPIRY", "Allowance has no expires_at, so the delegated credential never lapses."));
  else if (exp - now > 86400 && exp > now)
    flags.push(flag("warn", "ACP_LONG_EXPIRY", `Allowance stays chargeable for another ${duration(exp - now)}.`));
  if (a.reason !== undefined && a.reason !== "one_time")
    flags.push(flag("warn", "ACP_REASON", `Allowance reason is '${asText(a.reason)}', not 'one_time'.`));
  return {
    text: `up to ${amt} at merchant '${asText(a.merchant_id)}' for checkout ${asText(a.checkout_session_id)}${a.reason === "one_time" ? ", once" : ""}`,
    fields: [
      field("Max amount", amt, "amount", `${asText(a.max_amount)} minor units`),
      field("Merchant", asText(a.merchant_id, "")),
      field("Checkout session", asText(a.checkout_session_id, ""), "code"),
      field("Reason", asText(a.reason, "")),
      timeField("Expires", exp, now, a.expires_at),
    ],
    flags,
  };
}

export function decodeAcp(o: Obj, now: number): Decoded {
  if (isAcpDelegatePayment(o)) {
    const a = allowanceView(o.allowance as Obj, now);
    const pm = isRecord(o.payment_method) ? o.payment_method : {};
    const flags = [...a.flags];
    const card = `${asText(pm.display_brand, pm.type ?? "card")}${pm.display_last4 ? ` ending ${asText(pm.display_last4)}` : ""}`;
    if (typeof pm.number === "string" && pm.number.length >= 12) {
      flags.push(
        flag(
          "danger",
          "ACP_RAW_PAN",
          `Contains a full card number${pm.cvc ? " and CVC" : ""}. This request is PCI cardholder data: it should only ever travel from the agent platform to the PSP's vault, never be logged or pasted into tools.`,
        ),
      );
    }
    const risk = (Array.isArray(o.risk_signals) ? o.risk_signals : []).filter(isRecord) as Obj[];
    for (const r of risk) {
      if (r.action && r.action !== "authorized")
        flags.push(
          flag("warn", "ACP_RISK_SIGNAL", `Risk signal '${asText(r.type)}' (score ${asText(r.score)}) asks for '${asText(r.action)}'.`),
        );
    }
    return make(
      "acp.delegate-payment",
      "ACP delegate payment request",
      `Asks the PSP to vault ${card} so the agent can charge ${a.text}.`,
      [
        section("Allowance", a.fields),
        section("Payment method", [
          field("Type", asText(pm.type, "")),
          field("Card", card),
          ...(pm.exp_month ? [field("Expiry", `${asText(pm.exp_month)}/${asText(pm.exp_year)}`)] : []),
          ...(pm.number
            ? [field("Number", `${asText(pm.number).slice(0, 6)}…${asText(pm.number).slice(-4)}`, "code", "full PAN present (masked here)")]
            : []),
        ]),
        ...(risk.length
          ? [
              section(
                "Risk signals",
                risk.map((r) => field(asText(r.type), `score ${asText(r.score)}, action ${asText(r.action)}`)),
              ),
            ]
          : []),
      ],
      flags,
      o,
    );
  }
  if (isAcpAllowance(o)) {
    const a = allowanceView(o, now);
    return make("acp.allowance", "ACP allowance", `Lets the agent charge ${a.text}.`, [section("Allowance", a.fields)], a.flags, o);
  }
  if (isAcpPaymentData(o)) {
    const ins = o.instrument as Obj;
    const cred = isRecord(ins.credential) ? ins.credential : {};
    return make(
      "acp.payment-data",
      "ACP checkout payment data",
      `Completes checkout with a ${asText(ins.type, "payment")} via handler '${asText(o.handler_id)}' using ${asText(cred.type, "a credential")} token ${short(cred.token, 8, 4)}. Token not verified (needs the PSP).`,
      [
        section("Payment data", [
          field("Handler", asText(o.handler_id)),
          field("Instrument", asText(ins.type, "")),
          field("Credential type", asText(cred.type, "")),
          field("Token", asText(cred.token, ""), "code"),
        ]),
      ],
      [],
      o,
    );
  }
  const created = toUnix(o.created);
  return make(
    "acp.vault-token",
    "ACP delegated payment token",
    `PSP issued vault token ${asText(o.id)}${created !== undefined ? ` at ${formatTime(created)}` : ""}; the agent passes it to the merchant instead of card details.`,
    [
      section("Token", [
        field("Token id", asText(o.id), "code"),
        ...(created !== undefined ? [timeField("Created", created, now, o.created)] : []),
        ...(isRecord(o.metadata) ? [field("Metadata", JSON.stringify(o.metadata), "code")] : []),
      ]),
    ],
    [],
    o,
  );
}
