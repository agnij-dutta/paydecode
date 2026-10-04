// Object and string classification: routes a parsed value to the decoder whose shape it matches,
// and walks wrapper envelopes (MCP _meta, A2A metadata, JSON-RPC, AP2 bundled_token) to find artifacts.
import { base58 } from "@scure/base";
import { decodeAcp, isAcpAllowance, isAcpDelegatePayment, isAcpPaymentData, isAcpVaultToken } from "../acp.js";
import { decodeAp2X402Bundle, isAp2X402Bundle } from "../ap2/bundle.js";
import { decodeSdJwtChain } from "../ap2/chain.js";
import {
  decodeCartMandate,
  decodeIntentMandate,
  decodePaymentMandateV01,
  isCartMandate,
  isIntentMandate,
  isPaymentMandateV01,
} from "../ap2/legacy.js";
import { renderMandate } from "../ap2/mandates.js";
import { b64url, decodeBase64, isRecord, tryJson, utf8 } from "../core/encoding.js";
import { asText, field, flag, plural, section, sortFlags } from "../core/format.js";
import { make } from "../core/result.js";
import { looksLikeJwt, looksLikeSdJwt, parseJwt } from "../crypto/sdjwt.js";
import { decodeMppChallenge, decodeMppCredential, decodeMppReceipt } from "../mpp.js";
import { analyzeSvmTransaction } from "../svm/analyze.js";
import { looksLikeTransaction } from "../svm/parser.js";
import { decodeSignatureInput } from "../tap.js";
import type { Decoded, Flag } from "../types.js";
import { decodePaymentPayload } from "../x402/payload.js";
import { decodePaymentRequired } from "../x402/requirements.js";
import {
  decodeFacilitatorRequest,
  decodeRequirement,
  decodeSettleResponse,
  decodeSupported,
  decodeVerifyResponse,
} from "../x402/responses.js";
import {
  isFacilitatorRequest,
  isPaymentPayload,
  isPaymentRequired,
  isRequirement,
  isSettleResponse,
  isSupported,
  isVerifyResponse,
} from "../x402/shapes.js";

type Obj = Record<string, unknown>;

export interface Ctx {
  now: number;
  depth: number;
}

// ---------------------------------------------------------------- object classification

export function classifyObject(o: Obj, ctx: Ctx, endpointHint?: string): Decoded | undefined {
  const { now } = ctx;
  if (isAp2X402Bundle(o)) return decodeAp2X402Bundle(o, now);
  if (isFacilitatorRequest(o)) return decodeFacilitatorRequest(o, now, endpointHint);
  if (isPaymentPayload(o)) return decodePaymentPayload(o, now);
  if (isPaymentRequired(o)) return decodePaymentRequired(o, now);
  if (isSettleResponse(o)) return decodeSettleResponse(o);
  if (isVerifyResponse(o)) return decodeVerifyResponse(o);
  if (isSupported(o)) return decodeSupported(o);
  if (isRequirement(o)) return decodeRequirement(o);
  if (isIntentMandate(o)) return decodeIntentMandate(o, now);
  if (isCartMandate(o)) return decodeCartMandate(o, now, (v) => nested(v, ctx));
  if (isPaymentMandateV01(o)) return decodePaymentMandateV01(o, now, (v) => nested(v, ctx));
  if (isAcpDelegatePayment(o) || isAcpAllowance(o) || isAcpVaultToken(o) || isAcpPaymentData(o)) return decodeAcp(o, now);
  if (isRecord(o.challenge) && "method" in o.challenge && "payload" in o) {
    return decodeMppCredential(b64url(new TextEncoder().encode(JSON.stringify(o))), now);
  }
  if (typeof o.vct === "string" && o.vct.startsWith("mandate.")) {
    const v = renderMandate(o, now, "Mandate");
    return make(
      "ap2.mandate",
      `AP2 ${v.label.toLowerCase()} (decoded JSON)`,
      `${v.label}: ${v.english || "no constraints"}. This is the decoded claim set only; without the SD-JWT there's no signature to check.`,
      [section(v.label, v.fields)],
      [
        ...v.flags,
        flag(
          "warn",
          "MANDATE_UNSIGNED_JSON",
          "Plain JSON mandate: nothing proves who issued it. Paste the SD-JWT chain to verify signatures.",
        ),
      ],
      o,
    );
  }
  return undefined;
}

export const WRAPPER_NAMES: [string, string][] = [
  ["x402/payment", 'MCP _meta["x402/payment"]'],
  ["x402/payment-response", 'MCP _meta["x402/payment-response"]'],
  ["x402.payment.required", "A2A metadata x402.payment.required"],
  ["x402.payment.payload", "A2A metadata x402.payment.payload"],
  ["x402.payment.receipts", "A2A metadata x402.payment.receipts"],
  ["structuredContent", "MCP tool result structuredContent"],
  ["bundled_token", "AP2 credential provider bundled_token"],
  ["ap2.mandates.IntentMandate", "A2A DataPart ap2.mandates.IntentMandate"],
  ["ap2.mandates.CartMandate", "A2A DataPart ap2.mandates.CartMandate"],
  ["ap2.mandates.PaymentMandate", "A2A DataPart ap2.mandates.PaymentMandate"],
];

export interface Found {
  path: string;
  decoded: Decoded;
}

/** Walk a JSON structure looking for known artifacts (wrappers: MCP, A2A, JSON-RPC, AP2). */
export function walk(v: unknown, ctx: Ctx, path: string, out: Found[], depth = 0): void {
  if (depth > 8 || out.length > 20) return;
  if (typeof v === "string") {
    if (v.length < 24) return;
    const d = decodeString(v, { ...ctx, depth: ctx.depth + 1 });
    if (d) out.push({ path, decoded: d });
    return;
  }
  if (Array.isArray(v)) {
    v.forEach((x, i) => walk(x, ctx, `${path}[${i}]`, out, depth + 1));
    return;
  }
  if (!isRecord(v)) return;
  if (depth > 0) {
    const d = classifyObject(v, ctx);
    if (d) {
      out.push({ path, decoded: d });
      return;
    }
  }
  for (const [k, x] of Object.entries(v)) walk(x, ctx, path ? `${path}.${k}` : k, out, depth + 1);
}

export function wrapperLabel(path: string): string | undefined {
  for (const [key, label] of WRAPPER_NAMES) if (path.includes(key)) return label;
  return undefined;
}

export function container(found: Found[], raw: unknown, what: string): Decoded {
  if (found.length === 1) {
    const f = found[0];
    const label = wrapperLabel(f.path);
    const d = f.decoded;
    return {
      ...d,
      title: label ? `${d.title}, inside ${label}` : d.title,
      flags: sortFlags([
        ...d.flags,
        flag("info", "WRAPPED", `Found at ${f.path || "the top level"}${label ? ` (${label})` : ""} of the pasted ${what}.`),
      ]),
      raw,
      children: d.children,
    };
  }
  const flags: Flag[] = found.flatMap((f, i) =>
    f.decoded.flags.filter((x) => x.level === "danger" || x.level === "warn").map((x) => ({ ...x, message: `[${i + 1}] ${x.message}` })),
  );
  return make(
    "container",
    `${what[0].toUpperCase()}${what.slice(1)} with ${plural(found.length, "payment artifact")}`,
    found.map((f, i) => `[${i + 1}] ${f.decoded.summary}`).join(" "),
    [
      section(
        "Contents",
        found.map((f, i) => field(`[${i + 1}] ${f.decoded.title}`, f.path || "(top level)", "code", wrapperLabel(f.path))),
      ),
    ],
    flags,
    raw,
    found.map((f) => f.decoded),
  );
}

export function decodeJsonValue(v: unknown, ctx: Ctx, what: string, endpointHint?: string): Decoded | undefined {
  if (isRecord(v)) {
    const d = classifyObject(v, ctx, endpointHint);
    if (d) return d;
  }
  if (ctx.depth > 3) return undefined;
  const found: Found[] = [];
  walk(v, ctx, "", found);
  if (found.length) return container(found, v, what);
  return undefined;
}

/** Decode values nested in other artifacts (method_data, payment_response.details...). */
export function nested(v: unknown, ctx: Ctx): Decoded[] {
  if (v === undefined || v === null) return [];
  const c = { ...ctx, depth: ctx.depth + 1 };
  if (typeof v === "string") {
    const d = decodeString(v, c);
    return d ? [d] : [];
  }
  if (isRecord(v)) {
    const d = classifyObject(v, c);
    if (d) return [d];
  }
  const found: Found[] = [];
  walk(v, c, "", found);
  return found.map((f) => f.decoded);
}

// ---------------------------------------------------------------- strings

export function decodeJwt(s: string, ctx: Ctx): Decoded | undefined {
  const j = parseJwt(s);
  if (!j) return undefined;
  const inner = decodeJsonValue(j.payload, ctx, "JWT payload");
  const exp = typeof j.payload.exp === "number" ? j.payload.exp : undefined;
  const flags: Flag[] = [
    flag(
      "info",
      "JWT_UNVERIFIED",
      `JWT signature (${asText(j.header.alg)}${j.header.kid ? `, kid '${asText(j.header.kid)}'` : ""}) not verified: the signer's key isn't in the artifact.`,
    ),
  ];
  if (exp !== undefined && exp <= ctx.now) flags.push(flag("danger", "JWT_EXPIRED", "JWT has expired."));
  if (j.header.alg === "none") flags.push(flag("danger", "JWT_ALG_NONE", "alg is 'none': the token is unsigned."));
  return make(
    "jwt",
    "JWT",
    inner
      ? `Signed JWT carrying: ${inner.summary}`
      : `JWT (${asText(j.header.alg)}) with claims ${Object.keys(j.payload).slice(0, 8).join(", ")}. No known payment schema in its payload.`,
    [
      section(
        "Header",
        Object.entries(j.header).map(([k, v]) => field(k, typeof v === "string" ? v : JSON.stringify(v), "code")),
      ),
      section(
        "Payload",
        Object.entries(j.payload).map(([k, v]) => field(k, typeof v === "string" ? v : JSON.stringify(v), "code")),
      ),
    ],
    flags,
    { header: j.header, payload: j.payload },
    inner ? [inner] : [],
  );
}

export function decodeSolana(text: string, bytes: Uint8Array, ctx: Ctx): Decoded | undefined {
  if (!looksLikeTransaction(bytes)) return undefined;
  const a = analyzeSvmTransaction(text, bytes, {}, ctx.now);
  return make(
    "svm.transaction",
    "Solana transaction",
    a.summary,
    a.sections,
    [
      ...a.flags,
      flag(
        "info",
        "NO_REQUIREMENTS",
        "Bare transaction: without the x402 requirements, payTo, amount and fee payer can't be cross-checked. Paste the full PAYMENT-SIGNATURE or /verify body to check them.",
      ),
    ],
    { transaction: text },
  );
}

/** Decode a single (header-free) string value. Returns undefined if nothing matched. */
export function decodeString(s: string, ctx: Ctx, header?: string): Decoded | undefined {
  const text = s.trim();
  if (!text) return undefined;
  // MPP
  if (/^Payment\s+/i.test(text)) {
    const rest = text.replace(/^Payment\s+/i, "");
    if (/\bid\s*=/.test(rest) || header === "www-authenticate") return decodeMppChallenge(text, ctx.now);
    return decodeMppCredential(rest, ctx.now);
  }
  // RFC 9421 / TAP
  if (header === "signature-input" || /^[A-Za-z0-9_-]+=\("/.test(text)) {
    const d = decodeSignatureInput(text, ctx.now);
    if (d) return d;
  }
  // JSON
  const j = tryJson(text);
  if (j !== undefined) return decodeJsonValue(j, ctx, "JSON");
  // SD-JWT chain
  if (looksLikeSdJwt(text)) {
    const chain = decodeSdJwtChain(text, ctx.now);
    if (chain) return chain.decoded;
  }
  if (looksLikeJwt(text)) {
    const d = decodeJwt(text, ctx);
    if (d) return d;
  }
  // base64 / base64url
  const bytes = decodeBase64(text);
  if (bytes) {
    const inner = tryJson(utf8(bytes));
    if (inner !== undefined) {
      const d = decodeJsonValue(inner, ctx, "base64 JSON");
      if (d) return d;
      if (header === "payment-receipt") return decodeMppReceipt(text, ctx.now);
      return undefined;
    }
    const sol = decodeSolana(text, bytes, ctx);
    if (sol) return sol;
  }
  // base58 Solana tx
  if (/^[1-9A-HJ-NP-Za-km-z]{100,}$/.test(text)) {
    try {
      const b = base58.decode(text);
      const sol = decodeSolana(text, b, ctx);
      if (sol) return sol;
    } catch {
      /* not base58 */
    }
  }
  return undefined;
}
