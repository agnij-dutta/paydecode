// MPP: the HTTP "Payment" authentication scheme (WWW-Authenticate challenge, Authorization
// credential, Payment-Receipt).
// Spec: IETF draft-httpauth-payment-01, https://github.com/tempoxyz/mpp-specs/tree/main/specs/core
import { fromB64url, isRecord, parseJsonLoose, utf8 } from "./core/encoding.js";
import {
  asText,
  field,
  flag,
  formatMinor,
  formatTime,
  formatUnits,
  listJoin,
  relative,
  section,
  short,
  timeField,
  toUnix,
} from "./core/format.js";
import { EVM_TOKENS, findSplToken } from "./core/networks.js";
import { make } from "./core/result.js";
import type { Decoded, Field, Flag } from "./types.js";

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

export const b64Json = (s: unknown): unknown => {
  if (typeof s !== "string") return undefined;
  const b = fromB64url(s.replace(/=+$/, ""));
  return b ? parseJsonLoose(utf8(b)) : undefined;
};

export function mppAmount(req: Obj): string {
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

export function describeChallenge(
  p: Record<string, unknown>,
  now: number,
): { text: string; fields: Field[]; flags: Flag[]; request?: Obj } {
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
