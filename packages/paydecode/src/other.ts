// MPP (HTTP Payment auth scheme), ACP delegated payment, Visa TAP signatures.
import type { Decoded, Field, Flag } from "./types.js";
import { isRecord, fromB64url, utf8, parseJsonLoose } from "./encoding.js";
import {
  field,
  flag,
  formatMinor,
  formatUnits,
  formatTime,
  relative,
  short,
  section,
  timeField,
  toUnix,
  duration,
  listJoin,
} from "./format.js";
import { make } from "./x402.js";
import { EVM_TOKENS, findSplToken } from "./networks.js";
import { asText } from "./format.js";

type Obj = Record<string, unknown>;

// ---------------------------------------------------------------- MPP

/** Parse RFC 9110 auth-params: a="b", c=d */
export function parseAuthParams(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out[m[1].toLowerCase()] = m[2] !== undefined ? m[2].replace(/\\(.)/g, "$1") : m[3];
  return out;
}

const b64Json = (s: unknown): unknown => {
  if (typeof s !== "string") return undefined;
  const b = fromB64url(s.replace(/=+$/, ""));
  return b ? parseJsonLoose(utf8(b)) : undefined;
};

function mppAmount(req: Obj): string {
  const amount = req.amount;
  const cur = asText(req.currency, "");
  const md = isRecord(req.methodDetails) ? req.methodDetails : {};
  if (amount === undefined) return "an unstated amount";
  if (typeof md.decimals === "number") {
    const tk = EVM_TOKENS.find((t) => t.address.toLowerCase() === cur.toLowerCase()) ?? findSplToken(cur);
    return `${formatUnits(amount, md.decimals)} ${tk?.symbol ?? (cur.length > 12 ? short(cur) : cur)}`;
  }
  if (/^[A-Za-z]{3}$/.test(cur)) return formatMinor(amount, cur);
  if (cur === "sat" || cur === "sats") return `${asText(amount)} sats`;
  const tk = EVM_TOKENS.find((t) => t.address.toLowerCase() === cur.toLowerCase());
  if (tk) return `${formatUnits(amount, tk.decimals)} ${tk.symbol}`;
  const spl = findSplToken(cur);
  if (spl) return `${formatUnits(amount, spl.decimals)} ${spl.symbol}`;
  return `${asText(amount)} units of ${cur.length > 12 ? short(cur) : cur || "an unstated currency"}`;
}

function describeChallenge(p: Record<string, unknown>, now: number): { text: string; fields: Field[]; flags: Flag[]; request?: Obj } {
  const flags: Flag[] = [];
  const req = typeof p.request === "string" ? b64Json(p.request) : isRecord(p.request) ? p.request : undefined;
  const reqObj = isRecord(req) ? req : undefined;
  const intent = asText(p.intent, "charge");
  const exp = toUnix(p.expires);
  if (!p.id) flags.push(flag("danger", "MPP_NO_ID", "Challenge has no id; clients must reject it."));
  if (p.request !== undefined && !reqObj) flags.push(flag("warn", "MPP_REQUEST_UNREADABLE", "The request parameter isn't base64url JSON."));
  if (exp !== undefined && exp <= now) flags.push(flag("danger", "MPP_EXPIRED", `Challenge expired ${relative(exp, now)}.`));
  if (exp === undefined)
    flags.push(flag("info", "MPP_NO_EXPIRY", "No expires parameter; the server decides how long this challenge stays valid."));
  if (p.digest)
    flags.push(flag("ok", "MPP_BODY_BOUND", "Challenge is bound to the request body digest, so the paid request can't be swapped."));
  const amount = reqObj ? mppAmount(reqObj) : "an unstated amount";
  const recipient = reqObj?.recipient !== undefined ? asText(reqObj.recipient) : undefined;
  const what = intent === "charge" ? "a one-time charge" : intent === "subscription" ? "a subscription" : `a '${intent}' payment`;
  const text = `${what} of ${amount}${recipient ? ` to ${recipient.length > 20 ? short(recipient) : recipient}` : ""} via '${asText(p.method, "?")}'`;
  const fields: Field[] = [
    field("Challenge id", asText(p.id, ""), "code"),
    field("Realm", asText(p.realm, "")),
    field("Method", asText(p.method, "")),
    field("Intent", intent),
    field(
      "Amount",
      amount,
      "amount",
      reqObj?.amount !== undefined ? `raw ${asText(reqObj.amount)} ${asText(reqObj.currency, "")}` : undefined,
    ),
    ...(recipient ? [field("Recipient", recipient, "address")] : []),
    ...(reqObj?.description ? [field("Description", asText(reqObj.description))] : []),
    ...(reqObj?.externalId ? [field("External id", asText(reqObj.externalId))] : []),
    ...(reqObj && isRecord(reqObj.methodDetails) ? [field("Method details", JSON.stringify(reqObj.methodDetails), "code")] : []),
    ...(p.description ? [field("Description", asText(p.description))] : []),
    ...(exp !== undefined ? [timeField("Expires", exp, now, p.expires)] : []),
    ...(p.digest ? [field("Body digest", asText(p.digest), "hash")] : []),
    ...(p.header ? [field("Credential header", asText(p.header))] : []),
    ...(p.opaque ? [field("Opaque", JSON.stringify(b64Json(p.opaque) ?? p.opaque), "code")] : []),
  ];
  return { text, fields, flags, request: reqObj };
}

export function decodeMppChallenge(headerValue: string, now: number): Decoded {
  const challenges = headerValue
    .split(/(?:^|,)\s*Payment\s+/i)
    .map((s) => s.trim())
    .filter(Boolean)
    .map(parseAuthParams);
  const views = challenges.map((c) => describeChallenge(c, now));
  const realm = asText(challenges[0]?.realm, "the server");
  const summary =
    views.length === 1
      ? `${realm} asks for ${views[0].text}${challenges[0].expires ? `, offer ${toUnix(challenges[0].expires)! <= now ? "expired" : "expires"} ${formatTime(toUnix(challenges[0].expires)!)}` : ""}.${views[0].flags.some((f) => f.code === "MPP_EXPIRED") ? " The challenge has expired; ask the server for a fresh one." : " Pay by retrying the request with an Authorization: Payment credential."}`
      : `${realm} offers ${views.length} payment options: ${listJoin(
          views.map((v) => v.text),
          "or",
        )}.`;
  return make(
    "mpp.challenge",
    "MPP payment challenge (WWW-Authenticate: Payment)",
    summary,
    views.map((v, i) => section(views.length > 1 ? `Option ${i + 1}` : "Challenge", v.fields)),
    views.flatMap((v) => v.flags),
    challenges.map((c, i) => ({ ...c, request: views[i].request ?? c.request })),
  );
}

export function decodeMppCredential(token: string, now: number): Decoded | undefined {
  const cred = b64Json(token.trim());
  if (!isRecord(cred) || !isRecord(cred.challenge)) return undefined;
  const ch = describeChallenge(cred.challenge, now);
  const payload = isRecord(cred.payload) ? cred.payload : {};
  const flags: Flag[] = [...ch.flags.filter((f) => f.code !== "MPP_NO_EXPIRY")];
  flags.push(
    flag(
      "info",
      "MPP_PROOF_UNVERIFIED",
      `Payment proof (${Object.keys(payload).join(", ") || "empty"}) not verified: it's specific to method '${asText(cred.challenge.method)}' and needs the method's verifier or key.`,
    ),
  );
  if (!Object.keys(payload).length) flags.push(flag("danger", "MPP_NO_PROOF", "Credential carries no payment proof."));
  const summary = `MPP credential answering challenge ${short(cred.challenge.id, 8, 4)} from ${asText(cred.challenge.realm, "a server")}: claims to pay ${ch.text}${cred.source ? ` from ${asText(cred.source)}` : ""}. Proof not verified (no key).`;
  return make(
    "mpp.credential",
    "MPP payment credential (Authorization: Payment)",
    summary,
    [
      section("Echoed challenge", ch.fields),
      section("Payment proof", [
        ...(cred.source ? [field("Source (payer)", asText(cred.source), "address")] : []),
        ...Object.entries(payload).map(([k, v]) => field(k, typeof v === "string" ? v : JSON.stringify(v), "code")),
      ]),
    ],
    flags,
    { ...cred, challenge: { ...cred.challenge, request: ch.request ?? cred.challenge.request } },
  );
}

export function decodeMppReceipt(token: string, now: number): Decoded | undefined {
  const r = b64Json(token.trim());
  if (!isRecord(r) || typeof r.status !== "string" || !("method" in r)) return undefined;
  const ts = toUnix(r.timestamp);
  return make(
    "mpp.receipt",
    "MPP payment receipt",
    `Receipt: ${r.status === "success" ? "payment succeeded" : `status '${r.status}'`} via '${asText(r.method)}'${ts !== undefined ? ` at ${formatTime(ts)}` : ""}${r.reference ? `, reference ${short(r.reference, 10, 6)}` : ""}.`,
    [
      section("Receipt", [
        field("Status", asText(r.status)),
        field("Method", asText(r.method)),
        ...(ts !== undefined ? [timeField("Timestamp", ts, now, r.timestamp)] : []),
        ...(r.reference ? [field("Reference", asText(r.reference), "hash")] : []),
      ]),
    ],
    r.status === "success"
      ? [flag("ok", "MPP_PAID", "Server reports the payment settled.")]
      : [flag("warn", "MPP_RECEIPT_STATUS", `Receipts should only ever have status 'success'; got '${asText(r.status)}'.`)],
    r,
  );
}

// ---------------------------------------------------------------- ACP

export const isAcpDelegatePayment = (o: Obj) => isRecord(o.allowance) && ("payment_method" in o || "risk_signals" in o);
export const isAcpAllowance = (o: Obj) => typeof o.max_amount === "number" && "checkout_session_id" in o && "merchant_id" in o;
export const isAcpVaultToken = (o: Obj) => typeof o.id === "string" && /^vt_/.test(o.id) && "created" in o;
export const isAcpPaymentData = (o: Obj) => typeof o.handler_id === "string" && isRecord(o.instrument);

function allowanceView(a: Obj, now: number): { text: string; fields: Field[]; flags: Flag[] } {
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

// ---------------------------------------------------------------- Visa TAP (RFC 9421)

export function decodeSignatureInput(value: string, now: number, signature?: string): Decoded | undefined {
  const m = value.trim().match(/^([A-Za-z0-9_-]+)=\(([^)]*)\)\s*;?(.*)$/);
  if (!m) return undefined;
  const label = m[1];
  const components = [...m[2].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
  const params: Record<string, string> = {};
  for (const part of m[3].split(";")) {
    const kv = part.trim().match(/^([A-Za-z0-9_-]+)=(?:"([^"]*)"|(\S+))$/);
    if (kv) params[kv[1]] = kv[2] ?? kv[3];
  }
  const keyid = params.keyid ?? params.keyId ?? params.KeyId;
  for (const k of Object.keys(params)) if (k.toLowerCase() === "keyid") params.keyid = params[k];
  const created = toUnix(params.created);
  const expires = toUnix(params.expires);
  const tag = params.tag;
  const flags: Flag[] = [];
  const isTap = tag === "agent-browser-auth" || tag === "agent-payer-auth" || tag === "agent-payment-auth";
  if (expires !== undefined && expires <= now)
    flags.push(flag("danger", "TAP_EXPIRED", `Signature expired ${relative(expires, now)}; merchants must reject it.`));
  if (created !== undefined && created > now + 60)
    flags.push(flag("warn", "TAP_CREATED_FUTURE", `created is ${relative(created, now)}, in the future.`));
  if (created !== undefined && expires !== undefined && expires - created > 8 * 60) {
    flags.push(
      flag(
        "warn",
        "TAP_LONG_WINDOW",
        `Validity window is ${duration(expires - created)}; Visa's reference agent uses 8 minutes. Longer windows widen replay risk.`,
      ),
    );
  }
  if (!params.nonce) flags.push(flag("warn", "TAP_NO_NONCE", "No nonce, so merchants can't detect replays of this signature."));
  if (!components.includes("@authority") || !components.includes("@path")) {
    flags.push(
      flag(
        "warn",
        "TAP_WEAK_COVERAGE",
        `Covers only ${components.join(", ") || "nothing"}; TAP signs at least "@authority" and "@path" so the signature can't be moved to another site or page.`,
      ),
    );
  }
  flags.push(
    flag(
      "info",
      "TAP_UNVERIFIED",
      `Not verified (no key): fetch key '${keyid ?? "?"}' from the agent registry and rebuild the signature base from the request to check it.`,
    ),
  );
  const purpose =
    tag === "agent-payer-auth"
      ? "pay at checkout"
      : tag === "agent-browser-auth"
        ? "browse as a trusted agent"
        : tag
          ? `'${tag}'`
          : "an unstated purpose";
  const summary = `${isTap ? "Visa Trusted Agent Protocol signature" : "HTTP message signature (RFC 9421)"}: agent key ${keyid ? `'${keyid}'` : "(no keyid)"} signs ${listJoin(components.map((c) => `"${c}"`)) || "nothing"} to ${purpose}${expires !== undefined ? `, ${expires <= now ? "expired" : "valid until"} ${formatTime(expires)}` : ""}. Not verified (no key).`;
  return make(
    isTap ? "visa-tap.signature" : "http-signature",
    isTap ? "Visa TAP agent signature (Signature-Input)" : "HTTP message signature (Signature-Input)",
    summary,
    [
      section("Signature input", [
        field("Label", label, "code"),
        field("Covered components", components.join(" ") || "(none)", "code"),
        ...(keyid ? [field("Key id", keyid, "code")] : []),
        ...(params.alg ? [field("Algorithm", params.alg, "code")] : []),
        ...(tag ? [field("Tag", tag, "text", isTap ? purpose : undefined)] : []),
        ...(params.nonce ? [field("Nonce", params.nonce, "code")] : []),
        ...(created !== undefined ? [timeField("Created", created, now, params.created)] : []),
        ...(expires !== undefined ? [timeField("Expires", expires, now, params.expires)] : []),
        ...(signature ? [field("Signature", signature, "code")] : []),
      ]),
    ],
    flags,
    { label, components, params, ...(signature ? { signature } : {}) },
  );
}
