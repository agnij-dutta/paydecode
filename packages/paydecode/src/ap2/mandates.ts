// AP2 v0.2 mandate rendering: turns a disclosed mandate (by `vct`) into plain English.
// Schemas: https://github.com/google-agentic-commerce/AP2/tree/main/code/sdk/schemas/ap2
import { isRecord } from "../core/encoding.js";
import { asText, field, flag, formatMajor, formatMinor, formatTime, listJoin, relative, short, timeField, toUnix } from "../core/format.js";
import { parseJwt, sdHash } from "../crypto/sdjwt.js";
import type { Field, Flag } from "../types.js";

type Obj = Record<string, unknown>;

// ---------------------------------------------------------------- mandate English

export function merchantName(m: unknown): string {
  if (!isRecord(m)) return asText(m);
  const name = typeof m.name === "string" ? m.name : undefined;
  const id = typeof m.id === "string" ? m.id : undefined;
  if (name && id) return `${name} (${id})`;
  return name ?? id ?? (typeof m.website === "string" ? m.website : JSON.stringify(m));
}

export function instrumentName(i: unknown): string {
  if (!isRecord(i)) return asText(i);
  return asText(i.description, i.type ?? i.id ?? "instrument");
}

export function constraintPhrase(c: Obj): string {
  const t = asText(c.type, "");
  switch (t) {
    case "payment.amount_range": {
      const max = c.max !== undefined ? `max ${formatMinor(c.max, c.currency)} per payment` : "";
      const min = c.min !== undefined && Number(c.min) > 0 ? `min ${formatMinor(c.min, c.currency)}` : "";
      return [max, min].filter(Boolean).join(", ") || `amounts in ${asText(c.currency)}`;
    }
    case "payment.allowed_payees":
      return `only payee ${listJoin((Array.isArray(c.allowed) ? c.allowed : []).map(merchantName), "or") || "(none disclosed)"}`;
    case "payment.allowed_payment_instruments":
      return `only instrument ${listJoin(
        (Array.isArray(c.allowed) ? c.allowed : []).map((i) => (isRecord(i) ? asText(i.id, instrumentName(i)) : asText(i))),
        "or",
      )}`;
    case "payment.allowed_pisps":
      return `only via ${listJoin(
        (Array.isArray(c.allowed) ? c.allowed : []).map((p) =>
          isRecord(p) ? asText(p.brand_name, p.legal_name ?? p.domain_name) : asText(p),
        ),
        "or",
      )}`;
    case "payment.budget":
      return `total budget ${formatMajor(c.max, c.currency)}`;
    case "payment.agent_recurrence":
      return `${asText(c.frequency, "").toLowerCase().replace("_", "-")} payments${c.max_occurrences !== undefined ? `, at most ${asText(c.max_occurrences)} times` : ""}`;
    case "payment.execution_date": {
      const nb = toUnix(c.not_before);
      const na = toUnix(c.not_after);
      return `executed ${nb !== undefined ? `no earlier than ${formatTime(nb)}` : ""}${nb !== undefined && na !== undefined ? " and " : ""}${na !== undefined ? `no later than ${formatTime(na)}` : ""}`;
    }
    case "payment.reference":
      return `tied to checkout ${short(c.conditional_transaction_id, 6, 4)}`;
    case "checkout.allowed_merchants":
      return `only merchant ${listJoin((Array.isArray(c.allowed) ? c.allowed : []).map(merchantName), "or") || "(none disclosed)"}`;
    case "checkout.line_items": {
      const items = (Array.isArray(c.items) ? c.items : []).filter(isRecord).map((it) => {
        const acc = (Array.isArray(it.acceptable_items) ? it.acceptable_items : []).map((a) =>
          isRecord(a) ? asText(a.title, a.id) : asText(a),
        );
        return `${asText(it.quantity, 1)} x ${acc.length ? listJoin(acc, "or") : "(undisclosed item)"}`;
      });
      return `buy ${listJoin(items)}`;
    }
    default:
      return `${t || "constraint"} ${JSON.stringify(c)}`;
  }
}

export function mandateTimes(m: Obj, now: number): { phrase: string; flags: Flag[]; fields: Field[] } {
  const flags: Flag[] = [];
  const fields: Field[] = [];
  const exp = toUnix(m.exp);
  const iat = toUnix(m.iat);
  if (iat !== undefined) fields.push(timeField("Issued", iat, now, m.iat));
  if (exp !== undefined) fields.push(timeField("Expires", exp, now, m.exp));
  let phrase = "";
  if (exp !== undefined) phrase = exp <= now ? `expired ${relative(exp, now)}` : `expires ${formatTime(exp)}`;
  if (iat !== undefined && iat > now + 300)
    flags.push(flag("warn", "MANDATE_IAT_FUTURE", `Issued ${relative(iat, now)}, in the future. Clock skew or a forged timestamp.`));
  return { phrase, flags, fields };
}

export interface MandateView {
  vct: string;
  label: string;
  english: string;
  fields: Field[];
  flags: Flag[];
  open: boolean;
}

export function renderMandate(m: Obj, now: number, hopLabel: string): MandateView {
  const vct = asText(m.vct, "");
  const flags: Flag[] = [];
  const fields: Field[] = [field("Type (vct)", vct, "code")];
  const times = mandateTimes(m, now);
  flags.push(...times.flags.map((f) => ({ ...f, message: `${hopLabel}: ${f.message}` })));
  const constraints = (Array.isArray(m.constraints) ? m.constraints : []).filter(isRecord) as Obj[];
  let label: string;
  let english: string;
  const open = vct.includes(".open.");

  if (vct.startsWith("mandate.payment.open")) {
    label = "Open payment mandate";
    const phrases = constraints.map(constraintPhrase);
    if (isRecord(m.payee)) phrases.push(`payee ${merchantName(m.payee)}`);
    if (isRecord(m.payment_amount)) phrases.push(`exactly ${formatMinor(m.payment_amount.amount, m.payment_amount.currency)}`);
    english = phrases.join(", ");
    constraints.forEach((c) => fields.push(field(asText(c.type, "constraint"), constraintPhrase(c), "text")));
    if (!constraints.some((c) => c.type === "payment.amount_range" || c.type === "payment.budget") && !isRecord(m.payment_amount)) {
      flags.push(
        flag(
          "danger",
          "MANDATE_NO_AMOUNT_LIMIT",
          `${hopLabel}: open payment mandate has no amount_range, budget or fixed amount. The agent can close it for any amount.`,
        ),
      );
    }
    if (!constraints.some((c) => c.type === "payment.allowed_payees") && !isRecord(m.payee)) {
      flags.push(flag("warn", "MANDATE_ANY_PAYEE", `${hopLabel}: no allowed_payees constraint, so the agent may pay any merchant.`));
    }
    if (!constraints.some((c) => c.type === "payment.reference")) {
      flags.push(
        flag(
          "warn",
          "MANDATE_NO_REFERENCE",
          `${hopLabel}: missing the payment.reference constraint the AP2 schema requires (it ties the payment to a checkout).`,
        ),
      );
    }
  } else if (vct.startsWith("mandate.payment")) {
    label = "Closed payment mandate";
    const amt = isRecord(m.payment_amount) ? formatMinor(m.payment_amount.amount, m.payment_amount.currency) : "an unstated amount";
    english = `pay ${amt} to ${isRecord(m.payee) ? merchantName(m.payee) : "an unstated payee"}${isRecord(m.payment_instrument) ? ` with ${instrumentName(m.payment_instrument)}` : ""}`;
    fields.push(field("Amount", amt, "amount", isRecord(m.payment_amount) ? `${asText(m.payment_amount.amount)} minor units` : undefined));
    if (isRecord(m.payee))
      fields.push(field("Payee", merchantName(m.payee), "text", typeof m.payee.website === "string" ? m.payee.website : undefined));
    if (isRecord(m.payment_instrument))
      fields.push(
        field(
          "Instrument",
          instrumentName(m.payment_instrument),
          "text",
          `${asText(m.payment_instrument.type, "")} id ${asText(m.payment_instrument.id, "")}`,
        ),
      );
    if (isRecord(m.pisp))
      fields.push(field("PISP", asText(m.pisp.brand_name, m.pisp.legal_name ?? ""), "text", asText(m.pisp.domain_name, "")));
    if (m.transaction_id !== undefined) fields.push(field("Transaction id (checkout hash)", asText(m.transaction_id), "hash"));
    if (m.execution_date !== undefined) fields.push(field("Execution date", asText(m.execution_date), "time"));
    if (!isRecord(m.payment_amount))
      flags.push(flag("danger", "MANDATE_NO_AMOUNT", `${hopLabel}: closed payment mandate has no payment_amount.`));
  } else if (vct.startsWith("mandate.checkout.open")) {
    label = "Open checkout mandate";
    english = constraints.map(constraintPhrase).join(", ");
    constraints.forEach((c) => fields.push(field(asText(c.type, "constraint"), constraintPhrase(c), "text")));
    if (!constraints.some((c) => c.type === "checkout.allowed_merchants"))
      flags.push(
        flag("warn", "MANDATE_ANY_MERCHANT", `${hopLabel}: no allowed_merchants constraint, so any merchant's cart can close it.`),
      );
  } else if (vct.startsWith("mandate.checkout")) {
    label = "Closed checkout mandate";
    const cj = typeof m.checkout_jwt === "string" ? parseJwt(m.checkout_jwt) : undefined;
    if (cj) {
      const c = cj.payload;
      const items = (Array.isArray(c.line_items) ? c.line_items : []).filter(isRecord).map((li) => {
        const it = isRecord(li.item) ? li.item : {};
        return `${asText(li.quantity, 1)} x ${asText(it.title, it.id ?? "item")}`;
      });
      const total = Array.isArray(c.totals) ? (c.totals as Obj[]).find((tt) => isRecord(tt) && tt.type === "total") : undefined;
      english = `buy ${listJoin(items) || "an unlisted cart"} from ${isRecord(c.merchant) ? merchantName(c.merchant) : "an unstated merchant"}${total ? ` for ${formatMinor(total.amount, c.currency)}` : ""}`;
      fields.push(field("Merchant", isRecord(c.merchant) ? merchantName(c.merchant) : "not stated"));
      items.forEach((it, i) => fields.push(field(`Line item ${i + 1}`, it)));
      if (total) fields.push(field("Total", formatMinor(total.amount, c.currency), "amount"));
      if (typeof c.status === "string") fields.push(field("Checkout status", c.status));
      fields.push(
        field("Checkout JWT", "merchant-signed", "text", `kid ${asText(cj.header.kid, "?")}; not verified (merchant key not provided)`),
      );
      const computed = sdHash(asText(m.checkout_jwt));
      if (m.checkout_hash !== undefined) {
        if (computed === m.checkout_hash)
          flags.push(flag("ok", "CHECKOUT_HASH_OK", `${hopLabel}: checkout_hash matches sha256 of the embedded checkout JWT.`));
        else
          flags.push(
            flag(
              "danger",
              "CHECKOUT_HASH_MISMATCH",
              `${hopLabel}: checkout_hash ${short(m.checkout_hash, 8, 4)} does not match sha256 of the embedded checkout JWT (${short(computed, 8, 4)}). The cart was swapped after hashing.`,
            ),
          );
      }
    } else {
      english = `checkout ${short(m.checkout_hash, 8, 4)}`;
      if (m.checkout_jwt === undefined)
        flags.push(
          flag("info", "CHECKOUT_JWT_HIDDEN", `${hopLabel}: the checkout JWT wasn't disclosed, so the cart contents can't be shown.`),
        );
    }
    if (m.checkout_hash !== undefined) fields.push(field("Checkout hash", asText(m.checkout_hash), "hash"));
  } else {
    label = vct ? `Mandate (${vct})` : "Delegated payload";
    english = vct ? `${vct} mandate` : "an unrecognized delegated claim";
    for (const [k, v] of Object.entries(m))
      if (k !== "vct" && k !== "cnf") fields.push(field(k, typeof v === "string" ? v : JSON.stringify(v), "code"));
  }
  if (isRecord(m.cnf))
    fields.push(field("Delegated to key (cnf)", JSON.stringify(m.cnf.jwk ?? m.cnf), "code", "the next hop must be signed by this key"));
  fields.push(...times.fields);
  if (times.phrase && times.phrase.startsWith("expired")) {
    flags.push(
      flag(
        "danger",
        "MANDATE_EXPIRED",
        `${hopLabel}: ${label.toLowerCase()} ${times.phrase} (exp ${formatTime(toUnix(m.exp)!)}). Verifiers must reject it.`,
      ),
    );
  }
  if (open && m.exp === undefined)
    flags.push(flag("warn", "MANDATE_NO_EXPIRY", `${hopLabel}: open mandate has no exp, so the delegation never expires.`));
  if (times.phrase && !times.phrase.startsWith("expired") && english) english += `, ${times.phrase}`;
  return { vct, label, english, fields, flags, open };
}
