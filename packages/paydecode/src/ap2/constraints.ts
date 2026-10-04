// AP2 open-vs-closed mandate constraint checks, mirroring ap2.sdk.constraints
// (check_payment_constraints). Only the stateless subset can run offline.
// Source: https://github.com/google-agentic-commerce/AP2/blob/main/code/sdk/python/ap2/sdk/constraints.py
import { merchantName } from "./mandates.js";
import { isRecord } from "../core/encoding.js";
import { asText, currencyDecimals, formatMajor, formatMinor } from "../core/format.js";
import { parseJwt } from "../crypto/sdjwt.js";

type Obj = Record<string, unknown>;

/** Number(), but only for finite numeric values: a non-numeric amount must fail a check, never pass it. */
const num = (v: unknown): number | undefined => {
  if (typeof v !== "number" && typeof v !== "string") return undefined;
  if (typeof v === "string" && !v.trim()) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
};

// ---------------------------------------------------------------- cross checks

export function merchantMatches(candidate: unknown, target: unknown): boolean {
  if (!isRecord(candidate) || !isRecord(target)) return false;
  if (candidate.id && target.id) return candidate.id === target.id;
  return !!candidate.name && candidate.name === target.name && !!candidate.website && candidate.website === target.website;
}

/** Mirror of ap2.sdk.constraints.check_payment_constraints (stateless subset). */
export function checkPaymentConstraints(open: Obj, closed: Obj): { violations: string[]; checked: string[]; skipped: string[] } {
  const violations: string[] = [];
  const checked: string[] = [];
  const skipped: string[] = [];
  const amount = isRecord(closed.payment_amount) ? closed.payment_amount : undefined;
  for (const c of (Array.isArray(open.constraints) ? open.constraints : []).filter(isRecord) as Obj[]) {
    switch (c.type) {
      case "payment.amount_range":
        checked.push("amount range");
        if (!amount) violations.push("closed mandate has no payment_amount to check against amount_range");
        else {
          if (c.currency && amount.currency !== c.currency)
            violations.push(`currency is ${asText(amount.currency)} but the open mandate allows only ${asText(c.currency)}`);
          const paid = num(amount.amount);
          const max = c.max === undefined ? undefined : num(c.max);
          const min = c.min === undefined ? undefined : num(c.min);
          if (paid === undefined)
            violations.push(`payment amount '${asText(amount.amount)}' is not a number, so the range can't be satisfied`);
          else if (c.max !== undefined && max === undefined) violations.push(`amount_range max '${asText(c.max)}' is not a number`);
          else if (c.min !== undefined && min === undefined) violations.push(`amount_range min '${asText(c.min)}' is not a number`);
          else {
            if (max !== undefined && paid > max)
              violations.push(`${formatMinor(amount.amount, amount.currency)} exceeds the ${formatMinor(c.max, c.currency)} cap`);
            if (min !== undefined && paid < min)
              violations.push(`${formatMinor(amount.amount, amount.currency)} is below the ${formatMinor(c.min, c.currency)} minimum`);
          }
        }
        break;
      case "payment.allowed_payees":
        checked.push("payee");
        if (!(Array.isArray(c.allowed) && c.allowed.some((a) => merchantMatches(a, closed.payee))))
          violations.push(`payee ${merchantName(closed.payee)} is not in the allowed list`);
        break;
      case "payment.allowed_payment_instruments":
        checked.push("instrument");
        if (!isRecord(closed.payment_instrument)) violations.push("closed mandate has no payment_instrument");
        else if (!(Array.isArray(c.allowed) && c.allowed.some((a) => isRecord(a) && a.id === (closed.payment_instrument as Obj).id)))
          violations.push(`instrument ${asText((closed.payment_instrument as Obj).id)} is not allowed`);
        break;
      case "payment.allowed_pisps":
        checked.push("PISP");
        if (!isRecord(closed.pisp)) violations.push("closed mandate has no PISP");
        else if (!(
          Array.isArray(c.allowed) &&
          c.allowed.some(
            (a) =>
              isRecord(a) &&
              a.domain_name === (closed.pisp as Obj).domain_name &&
              a.legal_name === (closed.pisp as Obj).legal_name &&
              a.brand_name === (closed.pisp as Obj).brand_name,
          )
        ))
          violations.push("PISP is not in the allowed list");
        break;
      case "payment.budget":
        checked.push("budget currency");
        if (amount && amount.currency !== c.currency)
          violations.push(`budget is in ${asText(c.currency)} but the payment is in ${asText(amount.currency)}`);
        else if (amount) {
          // budget.max is in major units while payment_amount is in minor units: scale by the
          // currency's ISO 4217 exponent (JPY 0, USD 2, KWD 3), never a hard-coded 100.
          const dec = currencyDecimals(c.currency);
          const paid = num(amount.amount);
          const max = num(c.max);
          if (dec === undefined || paid === undefined || max === undefined)
            violations.push(
              `can't compare the payment (${asText(amount.amount)} ${asText(amount.currency)}) with the budget (${asText(c.max)} ${asText(c.currency)})`,
            );
          else if (paid > max * 10 ** dec)
            violations.push(
              `this single payment (${formatMinor(amount.amount, amount.currency)}) already exceeds the ${formatMajor(c.max, c.currency)} budget`,
            );
        }
        skipped.push("cumulative budget (needs spend history)");
        break;
      case "payment.execution_date": {
        checked.push("execution date");
        const ed = closed.execution_date;
        if (ed !== undefined) {
          if (c.not_before && asText(ed) < asText(c.not_before))
            violations.push(`execution date ${asText(ed)} is before ${asText(c.not_before)}`);
          if (c.not_after && asText(ed) > asText(c.not_after))
            violations.push(`execution date ${asText(ed)} is after ${asText(c.not_after)}`);
        }
        break;
      }
      case "payment.agent_recurrence":
        skipped.push("recurrence count (needs usage history)");
        break;
      case "payment.reference":
        skipped.push("checkout reference (needs the open checkout mandate's hash)");
        break;
      default:
        skipped.push(`unknown constraint ${asText(c.type)}`);
    }
  }
  if (
    isRecord(open.payment_amount) &&
    amount &&
    (open.payment_amount.amount !== amount.amount || open.payment_amount.currency !== amount.currency)
  ) {
    violations.push(
      `open mandate fixes the amount at ${formatMinor(open.payment_amount.amount, open.payment_amount.currency)} but the closed one pays ${formatMinor(amount.amount, amount.currency)}`,
    );
  }
  if (isRecord(open.payee) && !merchantMatches(open.payee, closed.payee))
    violations.push(`open mandate names payee ${merchantName(open.payee)} but the closed one pays ${merchantName(closed.payee)}`);
  return { violations, checked, skipped };
}

export function checkCheckoutConstraints(open: Obj, closed: Obj): { violations: string[]; checked: string[]; skipped: string[] } {
  const violations: string[] = [];
  const checked: string[] = [];
  const skipped: string[] = [];
  const cj = typeof closed.checkout_jwt === "string" ? parseJwt(closed.checkout_jwt) : undefined;
  if (!cj) return { violations, checked, skipped: ["all checkout constraints (checkout JWT not disclosed)"] };
  const checkout = cj.payload;
  for (const c of (Array.isArray(open.constraints) ? open.constraints : []).filter(isRecord) as Obj[]) {
    if (c.type === "checkout.allowed_merchants") {
      checked.push("merchant");
      if (!(Array.isArray(c.allowed) && c.allowed.some((a) => merchantMatches(a, checkout.merchant))))
        violations.push(`merchant ${merchantName(checkout.merchant)} is not in the allowed list`);
    } else if (c.type === "checkout.line_items") {
      checked.push("line items");
      const wanted = (Array.isArray(c.items) ? c.items : []).filter(isRecord) as Obj[];
      const lines = (Array.isArray(checkout.line_items) ? checkout.line_items : []).filter(isRecord) as Obj[];
      for (const li of lines) {
        const id = isRecord(li.item) ? li.item.id : undefined;
        const slot = wanted.find((w) => Array.isArray(w.acceptable_items) && w.acceptable_items.some((a) => isRecord(a) && a.id === id));
        if (!slot) violations.push(`cart item ${asText(id)} is not one of the acceptable items`);
        else if (!(Number(li.quantity ?? 1) <= Number(slot.quantity ?? 1)))
          violations.push(`cart has ${asText(li.quantity)} of ${asText(id)} but the mandate allows ${asText(slot.quantity)}`);
      }
    } else skipped.push(asText(c.type));
  }
  return { violations, checked, skipped };
}
