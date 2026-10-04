// AP2 v0.1 legacy JSON mandates (IntentMandate, CartMandate, PaymentMandate). The v0.1 doc examples
// disagree with the pydantic models; these decoders follow the models.
// Source: https://github.com/google-agentic-commerce/AP2/blob/main/code/sdk/python/ap2/models/mandate.py
import { isRecord } from "../core/encoding.js";
import { asText, field, flag, formatMajor, formatTime, listJoin, relative, section, short, timeField, toUnix } from "../core/format.js";
import { make } from "../core/result.js";
import { parseJwt } from "../crypto/sdjwt.js";
import type { Decoded, Field, Flag } from "../types.js";

type Obj = Record<string, unknown>;

// ---------------------------------------------------------------- AP2 v0.1 legacy

export const isIntentMandate = (o: Obj) =>
  "natural_language_description" in o && ("intent_expiry" in o || "user_cart_confirmation_required" in o);
export const isCartMandate = (o: Obj) => isRecord(o.contents) && isRecord((o.contents as Obj).payment_request);
export const isPaymentMandateV01 = (o: Obj) => isRecord(o.payment_mandate_contents);

export function paymentItemText(pi: unknown): string {
  if (!isRecord(pi)) return "an unstated amount";
  const a = isRecord(pi.amount) ? pi.amount : {};
  return formatMajor(a.value, a.currency);
}

export function decodeIntentMandate(o: Obj, now: number): Decoded {
  const flags: Flag[] = [];
  const exp = toUnix(o.intent_expiry);
  const merchants = Array.isArray(o.merchants) ? (o.merchants as unknown[]).map(String) : [];
  const skus = Array.isArray(o.skus) ? (o.skus as unknown[]).map(String) : [];
  if (exp === undefined) flags.push(flag("danger", "INTENT_NO_EXPIRY", "No intent_expiry: the agent's shopping authority never lapses."));
  else if (exp <= now) flags.push(flag("danger", "INTENT_EXPIRED", `Intent expired ${relative(exp, now)}.`));
  else if (exp - now > 30 * 86400)
    flags.push(flag("warn", "INTENT_LONG_EXPIRY", `Intent stays valid for another ${relative(exp, now).replace(/^in /, "")}.`));
  if (!merchants.length) flags.push(flag("warn", "INTENT_ANY_MERCHANT", "No merchant restriction: the agent may buy from any merchant."));
  if (o.user_cart_confirmation_required === false)
    flags.push(
      flag(
        "warn",
        "INTENT_NO_CART_CONFIRMATION",
        "user_cart_confirmation_required is false: the agent can buy without showing the user the final cart (human-not-present).",
      ),
    );
  if (!skus.length)
    flags.push(
      flag(
        "info",
        "INTENT_ANY_SKU",
        "No SKU restriction; the natural-language description is the only limit, and it isn't machine-enforceable.",
      ),
    );
  if (o.requires_refundability === true) flags.push(flag("ok", "INTENT_REFUNDABLE", "Only refundable items are allowed."));
  flags.push(
    flag("info", "AP2_V01_UNSIGNED", "AP2 v0.1 Intent Mandates carry no signature; v0.2 replaced them with signed SD-JWT open mandates."),
  );
  const summary = `AP2 v0.1 intent: "${asText(o.natural_language_description)}"${merchants.length ? `, only at ${listJoin(merchants, "or")}` : ", at any merchant"}, ${exp !== undefined ? (exp <= now ? `expired ${relative(exp, now)}` : `until ${formatTime(exp)}`) : "with no expiry"}${o.user_cart_confirmation_required === false ? ", without cart confirmation" : ""}.`;
  return make(
    "ap2.v01.intent-mandate",
    "AP2 v0.1 Intent Mandate",
    summary,
    [
      section("Intent", [
        field("Description", asText(o.natural_language_description, "")),
        field("Cart confirmation required", asText(o.user_cart_confirmation_required, "not set")),
        field("Merchants", merchants.length ? merchants.join(", ") : "any"),
        field("SKUs", skus.length ? skus.join(", ") : "any"),
        ...(o.requires_refundability !== undefined ? [field("Requires refundability", asText(o.requires_refundability))] : []),
        timeField("Intent expiry", exp, now, o.intent_expiry),
      ]),
    ],
    flags,
    o,
  );
}

export function decodeCartMandate(o: Obj, now: number, decodeNested: (v: unknown) => Decoded[]): Decoded {
  const c = o.contents as Obj;
  const pr = c.payment_request as Obj;
  const details = isRecord(pr.details) ? pr.details : {};
  const flags: Flag[] = [];
  const exp = toUnix(c.cart_expiry);
  const items = (Array.isArray(details.display_items) ? details.display_items : []).filter(isRecord) as Obj[];
  const methods = (Array.isArray(pr.method_data) ? pr.method_data : []).filter(isRecord) as Obj[];
  if (exp !== undefined && exp <= now) flags.push(flag("danger", "CART_EXPIRED", `Cart expired ${relative(exp, now)}.`));
  if (exp === undefined) flags.push(flag("warn", "CART_NO_EXPIRY", "No cart_expiry: the merchant's price commitment never lapses."));
  if (!o.merchant_authorization)
    flags.push(flag("warn", "CART_UNSIGNED", "No merchant_authorization: nothing proves the merchant offered this cart at this price."));
  const fields: Field[] = [
    field("Merchant", asText(c.merchant_name, "not stated")),
    field("Cart id", asText(c.id, "")),
    field("Total", paymentItemText(details.total), "amount", isRecord(details.total) ? asText(details.total.label, "") : undefined),
    ...items.map((it, i) =>
      field(
        `Item ${i + 1}`,
        `${asText(it.label, "item")}: ${paymentItemText(it)}`,
        "text",
        it.refund_period !== undefined ? `refund period ${asText(it.refund_period)} days` : undefined,
      ),
    ),
    field("Payment methods", methods.map((m) => asText(m.supported_methods)).join(", ") || "none"),
    field("Cart confirmation required", asText(c.user_cart_confirmation_required, "not set")),
    timeField("Cart expiry", exp, now, c.cart_expiry),
  ];
  if (typeof o.merchant_authorization === "string") {
    const j = parseJwt(o.merchant_authorization);
    fields.push(
      field(
        "Merchant authorization",
        j
          ? `JWT, alg ${asText(j.header.alg)}${j.payload.cart_hash ? `, cart_hash ${short(j.payload.cart_hash, 8, 4)}` : ""}`
          : short(o.merchant_authorization, 16, 8),
        "code",
        "not verified (merchant key not provided)",
      ),
    );
  }
  const children = methods.flatMap((m) => decodeNested(m.data));
  const x402 = methods.some((m) => asText(m.supported_methods).includes("x402"));
  const summary = `AP2 v0.1 cart from ${asText(c.merchant_name, "an unnamed merchant")}: ${items.length ? `${listJoin(items.map((i) => asText(i.label, "item")))} ` : ""}for ${paymentItemText(details.total)}${x402 ? ", payable over x402" : ""}, ${exp !== undefined ? (exp <= now ? `expired ${relative(exp, now)}` : `valid until ${formatTime(exp)}`) : "with no expiry"}.`;
  return make("ap2.v01.cart-mandate", "AP2 v0.1 Cart Mandate", summary, [section("Cart", fields)], flags, o, children);
}

export function decodePaymentMandateV01(o: Obj, now: number, decodeNested: (v: unknown) => Decoded[]): Decoded {
  const c = o.payment_mandate_contents as Obj;
  const resp = isRecord(c.payment_response) ? c.payment_response : {};
  const flags: Flag[] = [];
  const ts = toUnix(c.timestamp);
  if (!o.user_authorization)
    flags.push(
      flag(
        "danger",
        "PAYMENT_MANDATE_UNSIGNED",
        "No user_authorization: nothing proves the user approved this payment. A network or issuer should refuse it.",
      ),
    );
  const children = decodeNested(resp.details);
  if (typeof o.user_authorization === "string") children.push(...decodeNested(o.user_authorization));
  const fields: Field[] = [
    field("Payment mandate id", asText(c.payment_mandate_id, "")),
    field("Payment details id", asText(c.payment_details_id, "")),
    field("Total", paymentItemText(c.payment_details_total), "amount"),
    field("Method", asText(resp.method_name, "not stated")),
    field("Merchant agent", asText(c.merchant_agent, "not stated")),
    ...(ts !== undefined ? [timeField("Timestamp", ts, now, c.timestamp)] : []),
    field(
      "User authorization",
      o.user_authorization ? short(asText(o.user_authorization), 16, 8) : "missing",
      "code",
      o.user_authorization ? "not verified (user key not provided)" : undefined,
    ),
  ];
  const summary = `AP2 v0.1 payment of ${paymentItemText(c.payment_details_total)} via ${asText(resp.method_name, "an unstated method")} to merchant agent ${asText(c.merchant_agent, "unknown")}${o.user_authorization ? ", carrying a user authorization (not verified)" : ", with NO user authorization"}.`;
  return make("ap2.v01.payment-mandate", "AP2 v0.1 Payment Mandate", summary, [section("Payment", fields)], flags, o, children);
}
