// Visa Trusted Agent Protocol signatures: RFC 9421 HTTP Message Signatures (Signature-Input).
// Specs: https://www.rfc-editor.org/rfc/rfc9421 and https://github.com/visa/trusted-agent-protocol
import { duration, field, flag, formatTime, listJoin, relative, section, timeField, toUnix } from "./core/format.js";
import { make } from "./core/result.js";
import type { Decoded, Flag } from "./types.js";

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
