// AP2: v0.2 SD-JWT mandate chains, v0.1 legacy JSON mandates, and the
// AP2 x x402 credential bundle (EIP-3009 nonce = keccak256(mandate chain)).
import type { Decoded, Field, Flag, Section } from "./types.js";
import { isRecord } from "./encoding.js";
import { parseChain, parseJwt, verifyEs256, findCnfJwk, sdHash, type SdToken } from "./sdjwt.js";
import {
  field,
  flag,
  formatMinor,
  formatMajor,
  formatTime,
  relative,
  short,
  section,
  listJoin,
  toUnix,
  timeField,
  sentence,
} from "./format.js";
import { make } from "./x402.js";
import { analyzeEip3009 } from "./evm.js";
import { keccakUtf8, sameAddress } from "./eip712.js";
import { asText } from "./format.js";

type Obj = Record<string, unknown>;

// ---------------------------------------------------------------- mandate English

function merchantName(m: unknown): string {
  if (!isRecord(m)) return asText(m);
  const name = typeof m.name === "string" ? m.name : undefined;
  const id = typeof m.id === "string" ? m.id : undefined;
  if (name && id) return `${name} (${id})`;
  return name ?? id ?? (typeof m.website === "string" ? m.website : JSON.stringify(m));
}

function instrumentName(i: unknown): string {
  if (!isRecord(i)) return asText(i);
  return asText(i.description, i.type ?? i.id ?? "instrument");
}

function constraintPhrase(c: Obj): string {
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

function mandateTimes(m: Obj, now: number): { phrase: string; flags: Flag[]; fields: Field[] } {
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

// ---------------------------------------------------------------- cross checks

function merchantMatches(candidate: unknown, target: unknown): boolean {
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
          if (c.max !== undefined && Number(amount.amount) > Number(c.max))
            violations.push(`${formatMinor(amount.amount, amount.currency)} exceeds the ${formatMinor(c.max, c.currency)} cap`);
          if (c.min !== undefined && Number(amount.amount) < Number(c.min))
            violations.push(`${formatMinor(amount.amount, amount.currency)} is below the ${formatMinor(c.min, c.currency)} minimum`);
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
        else if (amount && Number(amount.amount) > Number(c.max) * 100)
          violations.push(
            `this single payment (${formatMinor(amount.amount, amount.currency)}) already exceeds the ${formatMajor(c.max, c.currency)} budget`,
          );
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
        else if (Number(li.quantity ?? 1) > Number(slot.quantity ?? 1))
          violations.push(`cart has ${asText(li.quantity)} of ${asText(id)} but the mandate allows ${asText(slot.quantity)}`);
      }
    } else skipped.push(asText(c.type));
  }
  return { violations, checked, skipped };
}

// ---------------------------------------------------------------- SD-JWT chains

const mandatesOf = (t: SdToken): Obj[] => (Array.isArray(t.resolved.delegate_payload) ? t.resolved.delegate_payload.filter(isRecord) : []);
const primaryMandate = (t: SdToken): Obj | undefined => mandatesOf(t).find((m) => typeof m.vct === "string") ?? mandatesOf(t)[0];

export interface ChainResult {
  decoded: Decoded;
  hops: SdToken[];
  closed?: Obj;
}

export function decodeSdJwtChain(input: string, now: number): ChainResult | undefined {
  const hops = parseChain(input);
  if (!hops || !hops.length) return undefined;
  const flags: Flag[] = [];
  const sections: Section[] = [];
  const views: MandateView[] = [];
  let sigVerified = 0;
  let sigUnchecked = 0;
  let sigBad = 0;
  let bindOk = 0;
  let bindBad = 0;

  hops.forEach((hop, i) => {
    const label = `Hop ${i + 1}`;
    const h = hop.jwt.header;
    const p = hop.jwt.payload;
    const typ = asText(h.typ, "");
    const isLast = i === hops.length - 1;
    const fields: Field[] = [
      field("JWT typ", typ || "(none)", "code"),
      field("Algorithm", asText(h.alg, "(none)"), "code", h.kid ? `kid ${asText(h.kid)}` : undefined),
    ];
    if (h.alg !== "ES256")
      flags.push(
        flag(
          h.alg === "none" ? "danger" : "warn",
          "HOP_ALG",
          `${label}: alg is '${asText(h.alg)}'; AP2 mandates are ES256.${h.alg === "none" ? " An unsigned mandate proves nothing." : ""}`,
        ),
      );

    // Signature
    if (i === 0) {
      const jwk = isRecord(h.jwk) ? h.jwk : undefined;
      if (jwk) {
        const ok = verifyEs256(hop.jwt, jwk);
        fields.push(
          field(
            "Signature",
            ok ? "valid (key embedded in header)" : "INVALID",
            "text",
            "an embedded key only proves self-consistency, not who issued it",
          ),
        );
        if (ok) sigVerified++;
        else {
          sigBad++;
          flags.push(flag("danger", "HOP_SIG_INVALID", `${label}: ES256 signature does not verify with the key in its own header.`));
        }
      } else {
        sigUnchecked++;
        fields.push(
          field(
            "Signature",
            "not verified (no key)",
            "text",
            `issuer key${h.kid ? ` '${asText(h.kid)}'` : ""} isn't included; check it against the agent provider's published key`,
          ),
        );
        flags.push(
          flag(
            "info",
            "ROOT_SIG_UNCHECKED",
            `${label}: the root issuer signature${h.kid ? ` (kid '${asText(h.kid)}')` : ""} wasn't verified because the issuer's public key isn't in the artifact.`,
          ),
        );
      }
    } else {
      const prev = hops[i - 1];
      const jwk = findCnfJwk(prev);
      if (!jwk) {
        sigUnchecked++;
        fields.push(field("Signature", "not verified (previous hop has no cnf key)", "text"));
        flags.push(
          flag(
            "danger",
            "HOP_UNBOUND",
            `${label}: hop ${i} carries no cnf key, so nothing binds this hop to whoever was delegated. Anyone holding hop ${i} could have appended it.`,
          ),
        );
      } else {
        const ok = verifyEs256(hop.jwt, jwk);
        fields.push(field("Signature", ok ? `valid (signed by hop ${i}'s cnf key)` : `INVALID under hop ${i}'s cnf key`, "text"));
        if (ok) sigVerified++;
        else {
          sigBad++;
          flags.push(
            flag(
              "danger",
              "HOP_SIG_INVALID",
              `${label}: ES256 signature does not verify with the cnf key delegated in hop ${i}. Either it was signed by a different key or its payload was edited.`,
            ),
          );
        }
      }
      // sd_hash / issuer_jwt_hash binding
      const alg = prev.jwt.payload._sd_alg ?? "sha-256";
      if (typeof p.sd_hash === "string") {
        const expected = sdHash(prev.sdJwt, alg);
        if (expected === p.sd_hash) {
          bindOk++;
          fields.push(field("sd_hash", p.sd_hash, "hash", `matches sha256 of hop ${i} (including the trailing ~)`));
        } else {
          bindBad++;
          fields.push(field("sd_hash", p.sd_hash, "hash", `does NOT match hop ${i} (expected ${short(expected, 8, 4)})`));
          flags.push(
            flag(
              "danger",
              "SD_HASH_MISMATCH",
              `${label}: sd_hash doesn't match hop ${i}. This hop was signed over a different version of the previous mandate (disclosures added, removed or edited).`,
            ),
          );
        }
      } else if (typeof p.issuer_jwt_hash === "string") {
        const expected = sdHash(prev.jwt.raw, alg);
        if (expected === p.issuer_jwt_hash) {
          bindOk++;
          fields.push(field("issuer_jwt_hash", p.issuer_jwt_hash, "hash", `matches hop ${i}'s issuer JWT`));
        } else {
          bindBad++;
          flags.push(flag("danger", "SD_HASH_MISMATCH", `${label}: issuer_jwt_hash doesn't match hop ${i}'s issuer JWT.`));
        }
      } else {
        bindBad++;
        flags.push(
          flag(
            "danger",
            "HOP_NO_SD_HASH",
            `${label}: no sd_hash or issuer_jwt_hash, so this hop isn't bound to the mandate it claims to extend.`,
          ),
        );
      }
      if (!typ.startsWith("kb+sd-jwt")) flags.push(flag("warn", "HOP_TYP", `${label}: typ '${typ}' is not kb+sd-jwt / kb+sd-jwt+kb.`));
      if (p.aud !== undefined) fields.push(field("Audience", asText(p.aud)));
      if (p.nonce !== undefined) fields.push(field("Nonce", asText(p.nonce), "code"));
    }
    const jexp = toUnix(p.exp);
    const jiat = toUnix(p.iat);
    if (jiat !== undefined) fields.push(timeField("JWT issued", jiat, now, p.iat));
    if (jexp !== undefined) {
      fields.push(timeField("JWT expires", jexp, now, p.exp));
      if (jexp <= now) flags.push(flag("danger", "HOP_EXPIRED", `${label}: the JWT expired ${relative(jexp, now)}.`));
    }
    fields.push(field("Disclosures", `${hop.disclosures.length} revealed${hop.undisclosed ? `, ${hop.undisclosed} kept hidden` : ""}`));
    const unused = hop.disclosures.filter((d) => !d.used);
    if (unused.length)
      flags.push(
        flag(
          "warn",
          "DISCLOSURE_UNUSED",
          `${label}: ${unused.length} disclosure(s) don't match any digest in the JWT. They were attached but are not covered by the signature, so ignore their contents.`,
        ),
      );

    const mandate = primaryMandate(hop);
    if (mandate) {
      const v = renderMandate(mandate, now, label);
      views.push(v);
      flags.push(...v.flags);
      const hasCnf = isRecord(mandate.cnf) || isRecord(hop.resolved.cnf);
      if (isLast && v.open && !hasCnf)
        flags.push(
          flag(
            "danger",
            "OPEN_MANDATE_UNBOUND",
            `${label}: open mandate has no cnf key, so it isn't bound to any agent. Whoever holds it can close it.`,
          ),
        );
      if (isLast && v.open && hasCnf)
        flags.push(
          flag(
            "info",
            "OPEN_MANDATE_PENDING",
            `${label}: this open mandate hasn't been closed yet. Only the holder of its cnf key can close it.`,
          ),
        );
      if (isLast && !v.open && hasCnf && hops.length > 1)
        flags.push(
          flag("warn", "TERMINAL_HAS_CNF", `${label}: the terminal (closed) hop carries a cnf claim; AP2 says terminal hops must not.`),
        );
      sections.push(section(`${label}: ${v.label}`, [...v.fields, ...fields]));
    } else {
      flags.push(flag("warn", "HOP_NO_MANDATE", `${label}: no delegate_payload mandate was disclosed.`));
      sections.push(section(`${label}: SD-JWT`, [...fields, field("Claims", JSON.stringify(hop.resolved), "code")]));
    }
  });

  // Cross-check consecutive open -> closed pairs
  const crossLines: string[] = [];
  let crossOk = true;
  let crossRan = false;
  for (let i = 0; i + 1 < hops.length; i++) {
    const a = primaryMandate(hops[i]);
    const b = primaryMandate(hops[i + 1]);
    if (!a || !b) continue;
    const va = asText(a.vct, "");
    const vb = asText(b.vct, "");
    let res: ReturnType<typeof checkPaymentConstraints> | undefined;
    if (va.startsWith("mandate.payment.open") && vb.startsWith("mandate.payment") && !vb.includes(".open."))
      res = checkPaymentConstraints(a, b);
    else if (va.startsWith("mandate.checkout.open") && vb.startsWith("mandate.checkout") && !vb.includes(".open."))
      res = checkCheckoutConstraints(a, b);
    if (!res) continue;
    crossRan = true;
    if (res.violations.length) {
      crossOk = false;
      for (const v of res.violations)
        flags.push(flag("danger", "MANDATE_CONSTRAINT_VIOLATION", `Hop ${i + 2} breaks hop ${i + 1}'s constraints: ${v}.`));
    } else if (res.checked.length) {
      flags.push(
        flag(
          "ok",
          "MANDATE_WITHIN_CONSTRAINTS",
          `Hop ${i + 2} stays within hop ${i + 1}'s constraints (checked ${listJoin(res.checked)}).`,
        ),
      );
    }
    if (res.skipped.length) flags.push(flag("info", "MANDATE_CONSTRAINTS_SKIPPED", `Not checkable offline: ${listJoin(res.skipped)}.`));
    crossLines.push(...res.checked.map((c) => `${c}: ok`), ...res.violations);
  }

  // Summary
  const kindWord = views.some((v) => v.vct.startsWith("mandate.checkout")) ? "checkout" : "payment";
  const parts: string[] = [];
  const openV = views.find((v) => v.open);
  const closedV = [...views].reverse().find((v) => !v.open);
  if (openV && closedV) {
    parts.push(
      `AP2 ${kindWord} mandate chain (${hops.length} hops): the user's open mandate ${kindWord === "checkout" ? "lets the agent " : "allows "}${openV.english || "unstated limits"}; the agent closed it to ${closedV.english}${crossRan ? (crossOk ? ", within those limits" : ", BREAKING those limits") : ""}.`,
    );
  } else if (openV) {
    parts.push(
      `AP2 open ${kindWord} mandate: lets the delegated agent ${kindWord === "payment" ? "pay with" : "check out with"} ${openV.english || "unstated limits"}.`,
    );
  } else if (closedV) {
    parts.push(`AP2 closed ${kindWord} mandate: ${closedV.english}.`);
  } else parts.push(`SD-JWT delegation chain with ${hops.length} hop(s).`);
  const sigBits: string[] = [];
  if (sigBad || bindBad) sigBits.push(`${sigBad + bindBad} signature/binding check(s) FAILED`);
  else if (sigVerified || bindOk) sigBits.push(`${hops.length > 1 ? "agent signature and sd_hash binding verify" : "signature verifies"}`);
  if (sigUnchecked) sigBits.push("the root issuer signature isn't checked (no key)");
  const expired = flags.some((f) => f.code === "MANDATE_EXPIRED" || f.code === "HOP_EXPIRED");
  if (expired) sigBits.push("the mandate has expired");
  if (sigBits.length)
    parts.push(
      sentence(sigBits[0][0].toUpperCase() + sigBits[0].slice(1) + (sigBits.length > 1 ? `; ${sigBits.slice(1).join("; ")}` : "")),
    );

  sections.unshift(
    section("Chain", [
      field("Hops", asText(hops.length)),
      ...views.map((v, i) => field(`Hop ${i + 1}`, v.label, "text", v.english)),
      ...(crossLines.length
        ? [
            field(
              "Cross-check",
              crossOk ? "closed mandate is within the open mandate" : "VIOLATES the open mandate",
              "text",
              crossLines.join("; "),
            ),
          ]
        : []),
    ]),
  );
  const closed = [...hops]
    .reverse()
    .map(primaryMandate)
    .find((m) => m && !asText(m.vct, "").includes(".open."));
  return {
    decoded: make(
      "ap2.mandate-chain",
      `AP2 ${kindWord} mandate${hops.length > 1 ? " chain" : ""} (SD-JWT)`,
      parts.join(" "),
      sections,
      flags,
      hops.map((h) => ({ header: h.jwt.header, payload: h.resolved })),
    ),
    hops,
    closed,
  };
}

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
    if (cur === "USD") {
      try {
        const expected = BigInt(asText(pa.amount)) * 10000n; // cents -> 6-decimal USDC
        const v = BigInt(asText(auth.value, "0"));
        if (v === expected)
          flags.push(
            flag(
              "ok",
              "AP2_AMOUNT_MATCHES",
              `On-chain amount matches the closed mandate (${formatMinor(pa.amount, pa.currency)} as 6-decimal USDC).`,
            ),
          );
        else
          flags.push(
            flag(
              "danger",
              "AP2_AMOUNT_MISMATCH",
              `The EIP-3009 value (${asText(auth.value)} units) doesn't equal the closed mandate's ${formatMinor(pa.amount, pa.currency)} (${expected} units at 6 decimals).`,
            ),
          );
      } catch {
        /* ignore */
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

// ---------------------------------------------------------------- AP2 v0.1 legacy

export const isIntentMandate = (o: Obj) =>
  "natural_language_description" in o && ("intent_expiry" in o || "user_cart_confirmation_required" in o);
export const isCartMandate = (o: Obj) => isRecord(o.contents) && isRecord((o.contents as Obj).payment_request);
export const isPaymentMandateV01 = (o: Obj) => isRecord(o.payment_mandate_contents);

function paymentItemText(pi: unknown): string {
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
