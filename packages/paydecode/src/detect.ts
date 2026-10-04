// Auto-detection: figure out what was pasted and route it to the right decoder.
import type { Decoded, DecodeOptions, Flag, Unrecognized } from "./types.js";
import { unwrapHeader, decodeBase64, utf8, tryJson, isRecord, b64url } from "./encoding.js";
import { base58 } from "@scure/base";
import { field, flag, section, sortFlags, short, plural } from "./format.js";
import {
  make,
  isPaymentRequired,
  isPaymentPayload,
  isSettleResponse,
  isVerifyResponse,
  isFacilitatorRequest,
  isSupported,
  isRequirement,
  decodePaymentRequired,
  decodePaymentPayload,
  decodeSettleResponse,
  decodeVerifyResponse,
  decodeFacilitatorRequest,
  decodeSupported,
  decodeRequirement,
} from "./x402.js";
import {
  isAp2X402Bundle,
  decodeAp2X402Bundle,
  decodeSdJwtChain,
  isIntentMandate,
  isCartMandate,
  isPaymentMandateV01,
  decodeIntentMandate,
  decodeCartMandate,
  decodePaymentMandateV01,
  renderMandate,
} from "./ap2.js";
import { looksLikeJwt, looksLikeSdJwt, parseJwt } from "./sdjwt.js";
import {
  decodeMppChallenge,
  decodeMppCredential,
  decodeMppReceipt,
  decodeSignatureInput,
  decodeAcp,
  isAcpDelegatePayment,
  isAcpAllowance,
  isAcpVaultToken,
  isAcpPaymentData,
} from "./other.js";
import { analyzeSvmTransaction, looksLikeTransaction } from "./svm.js";
import { asText } from "./format.js";

type Obj = Record<string, unknown>;

/** Machine id of what `detect` thinks the input is, without fully decoding it. */
export interface Detection {
  /** Same values as Decoded.kind ("x402.payment-payload", "ap2.mandate-chain", ...) or "unknown". */
  kind: string;
  /** Header name the user pasted, lowercased, if any. */
  header?: string;
  /** How the value was encoded: "json", "base64-json", "sd-jwt", "jwt", "solana-tx", "auth-params", "http", "curl". */
  encoding?: string;
}

interface Ctx {
  now: number;
  depth: number;
}

// ---------------------------------------------------------------- object classification

function classifyObject(o: Obj, ctx: Ctx, endpointHint?: string): Decoded | undefined {
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

const WRAPPER_NAMES: [string, string][] = [
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

interface Found {
  path: string;
  decoded: Decoded;
}

/** Walk a JSON structure looking for known artifacts (wrappers: MCP, A2A, JSON-RPC, AP2). */
function walk(v: unknown, ctx: Ctx, path: string, out: Found[], depth = 0): void {
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

function wrapperLabel(path: string): string | undefined {
  for (const [key, label] of WRAPPER_NAMES) if (path.includes(key)) return label;
  return undefined;
}

function container(found: Found[], raw: unknown, what: string): Decoded {
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

function decodeJsonValue(v: unknown, ctx: Ctx, what: string, endpointHint?: string): Decoded | undefined {
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
function nested(v: unknown, ctx: Ctx): Decoded[] {
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

function decodeJwt(s: string, ctx: Ctx): Decoded | undefined {
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

function decodeSolana(text: string, bytes: Uint8Array, ctx: Ctx): Decoded | undefined {
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
function decodeString(s: string, ctx: Ctx, header?: string): Decoded | undefined {
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

// ---------------------------------------------------------------- HTTP / curl pastes

const KNOWN_HEADERS =
  /^(x-payment-response|x-payment|payment-required|payment-signature|payment-response|payment-receipt|payment-authorization|www-authenticate|authorization|signature-input|signature|extension-responses)$/i;

interface HttpPaste {
  headers: { name: string; value: string }[];
  body?: string;
  status?: string;
}

function parseHttpPaste(input: string): HttpPaste | undefined {
  const t = input.trim();
  // curl -H '...' --header "..."
  if (/^curl\s/.test(t) || /(^|\s)(-H|--header)\s+['"]/.test(t)) {
    const headers = [...t.matchAll(/(?:-H|--header)\s+(['"])(.*?)\1/gs)]
      .map((m) => m[2])
      .map((h) => {
        const i = h.indexOf(":");
        return { name: h.slice(0, i).trim(), value: h.slice(i + 1).trim() };
      });
    const dm = t.match(/(?:-d|--data(?:-raw|-binary)?)\s+(['"])(.*?)\1/s);
    if (headers.length || dm) return { headers: headers.filter((h) => KNOWN_HEADERS.test(h.name)), body: dm?.[2] };
  }
  const lines = t.split(/\r?\n/);
  if (lines.length < 2 && !/^HTTP\//.test(t)) return undefined;
  const headers: { name: string; value: string }[] = [];
  let status: string | undefined;
  let i = 0;
  if (/^HTTP\/[\d.]+\s+\d+/.test(lines[0]) || /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+/.test(lines[0])) {
    status = lines[0].trim();
    i = 1;
  }
  let sawHeader = false;
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      break;
    }
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].value += " " + line.trim();
      continue;
    }
    const m = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
    if (!m) {
      if (!sawHeader) return undefined;
      break;
    }
    sawHeader = true;
    headers.push({ name: m[1], value: m[2].trim() });
  }
  if (!sawHeader) return undefined;
  const body = lines.slice(i).join("\n").trim() || undefined;
  return { headers: headers.filter((h) => KNOWN_HEADERS.test(h.name)), body, status };
}

function decodeHeaderValue(name: string, value: string, ctx: Ctx): Decoded | undefined {
  const h = name.toLowerCase();
  if (h === "payment-receipt") {
    const r = decodeMppReceipt(value, ctx.now);
    if (r) return r;
  }
  if ((h === "authorization" || h === "payment-authorization") && /^Payment\s+/i.test(value))
    return decodeMppCredential(value.replace(/^Payment\s+/i, ""), ctx.now);
  if (h === "www-authenticate" && /^Payment\s+/i.test(value)) return decodeMppChallenge(value, ctx.now);
  if (h === "signature-input") return decodeSignatureInput(value, ctx.now);
  if (h === "signature") return undefined;
  return decodeString(value, ctx, h);
}

// ---------------------------------------------------------------- public

function unrecognized(input: string, header?: string): Unrecognized {
  const text = input.trim();
  const sections = [];
  let summary: string;
  let raw: unknown = text;
  const flags: Flag[] = [];
  const j = tryJson(text);
  const bytes = j === undefined ? decodeBase64(text) : null;
  const bj = bytes ? tryJson(utf8(bytes)) : undefined;
  if (j !== undefined || bj !== undefined) {
    const val = j ?? bj;
    raw = val;
    summary =
      j !== undefined
        ? "This is valid JSON, but no known payment schema matched it. The parsed JSON is below."
        : "This is base64-encoded JSON, but no known payment schema matched it. Here's the decoded JSON.";
    if (isRecord(val))
      sections.push(
        section(
          "Top-level keys",
          Object.entries(val).map(([k, v]) => field(k, typeof v === "string" ? v : JSON.stringify(v), "code")),
        ),
      );
    if (isRecord(val) && "x402Version" in val)
      flags.push(
        flag("warn", "X402_PARTIAL", "Has x402Version but is missing the fields of any x402 message (accepts, payload, accepted...)."),
      );
  } else if (/^(0x)?[0-9a-fA-F]{130}$/.test(text)) {
    summary =
      "Looks like a bare 65-byte ECDSA signature. A signature alone can't be explained: paste the whole payload (signature plus the authorization it signs).";
  } else if (/^0x[0-9a-fA-F]{64}$/.test(text)) {
    summary =
      "Looks like a 32-byte hash (a transaction hash or EIP-3009 nonce). Look it up in a block explorer; there's nothing to decode on its own.";
  } else if (/^0x[0-9a-fA-F]{40}$/.test(text)) {
    summary = "That's an EVM address, not a payment artifact.";
  } else if (bytes) {
    summary = `Decodes from base64 to ${bytes.length} bytes of binary that isn't JSON or a Solana transaction.`;
    sections.push(
      section("Bytes", [
        field("Hex (first 64 bytes)", "0x" + [...bytes.slice(0, 64)].map((b) => b.toString(16).padStart(2, "0")).join(""), "code"),
      ]),
    );
  } else if (looksLikeJwt(text) || looksLikeSdJwt(text)) {
    summary = "Looks like a JWT or SD-JWT, but its segments don't decode to JSON.";
  } else {
    summary = `Not JSON, base64, a JWT/SD-JWT, or a known payment header${text.length > 0 ? ` (starts with "${short(text, 16, 0).replace(/…$/, "")}")` : ""}.`;
  }
  if (header) flags.push(flag("info", "HEADER_SEEN", `Pasted with header '${header}'.`));
  return { kind: "unknown", title: "Unrecognized input", summary, sections, flags, raw };
}

function nowOf(opts?: DecodeOptions): number {
  return opts?.now ?? Math.floor(Date.now() / 1000);
}

/**
 * Decode any agent-payment artifact into plain English plus risk flags.
 * Never throws: malformed input yields an `Unrecognized` with hints.
 */
export function decode(input: string, opts?: DecodeOptions): Decoded | Unrecognized {
  const ctx: Ctx = { now: nowOf(opts), depth: 0 };
  try {
    if (typeof input !== "string" || !input.trim()) {
      return {
        kind: "unknown",
        title: "Nothing to decode",
        summary: "Paste an x402 header, AP2 mandate, payment JSON or Solana transaction.",
        sections: [],
        flags: [],
        raw: input,
      };
    }
    const http = parseHttpPaste(input);
    if (http && (http.headers.length || http.body)) {
      const found: Found[] = [];
      for (const h of http.headers) {
        const d = decodeHeaderValue(h.name, h.value, ctx);
        if (d) found.push({ path: h.name, decoded: d });
      }
      if (http.body) {
        const endpoint = http.status?.match(/\/(verify|settle)\b/)?.[1];
        const j = tryJson(http.body);
        const d = j !== undefined ? decodeJsonValue(j, ctx, "body", endpoint) : decodeString(http.body, ctx);
        if (d) found.push({ path: "body", decoded: d });
      }
      if (found.length === 1 && !http.status && !http.body) {
        const d = found[0].decoded;
        d.flags = sortFlags([...d.flags, flag("info", "HEADER_SEEN", `Pasted as the ${found[0].path.toUpperCase()} header.`)]);
        return d;
      }
      if (found.length) {
        const c = container(
          found,
          { status: http.status, headers: http.headers, body: http.body },
          http.status?.startsWith("HTTP") ? "HTTP response" : "HTTP request",
        );
        return c;
      }
    }
    const { header, text } = unwrapHeader(input);
    const d = header ? decodeHeaderValue(header, text, ctx) : decodeString(text, ctx);
    if (d) {
      if (header) d.flags = sortFlags([...d.flags, flag("info", "HEADER_SEEN", `Pasted as the ${header.toUpperCase()} header.`)]);
      return d;
    }
    return unrecognized(text, header);
  } catch (e) {
    const u = unrecognized(input);
    u.flags.push(flag("warn", "DECODER_ERROR", `Decoder error: ${(e as Error).message}`));
    return u;
  }
}

/** Identify the artifact type without returning the full explanation. */
export function detect(input: string): Detection {
  const { header } = unwrapHeader(asText(input, ""));
  const d = decode(asText(input, ""), { now: 0 });
  const t = asText(input, "").trim();
  let encoding: string | undefined;
  if (/^curl\s/.test(t)) encoding = "curl";
  else if (/^HTTP\//.test(t) || /\n[A-Za-z-]+:\s/.test(t)) encoding = "http";
  else {
    const v = unwrapHeader(t).text;
    if (/^Payment\s/i.test(v) || /^[A-Za-z0-9_-]+=\("/.test(v)) encoding = "auth-params";
    else if (tryJson(v) !== undefined) encoding = "json";
    else if (looksLikeSdJwt(v)) encoding = "sd-jwt";
    else if (looksLikeJwt(v)) encoding = "jwt";
    else if (d.kind === "svm.transaction") encoding = "solana-tx";
    else if (decodeBase64(v)) encoding = tryJson(utf8(decodeBase64(v)!)) !== undefined ? "base64-json" : "base64";
  }
  return { kind: d.kind, ...(header ? { header } : {}), ...(encoding ? { encoding } : {}) };
}
