// Public entry points: decode() and detect().
import { decodeBase64, tryJson, unwrapHeader, utf8 } from "../core/encoding.js";
import { asText, flag, sortFlags } from "../core/format.js";
import { looksLikeJwt, looksLikeSdJwt } from "../crypto/sdjwt.js";
import { container, decodeJsonValue, decodeString } from "./classify.js";
import type { Ctx, Found } from "./classify.js";
import { decodeHeaderValue, parseHttpPaste } from "./http.js";
import { unrecognized } from "./unrecognized.js";
import type { DecodeOptions, Decoded, Unrecognized } from "../types.js";

/** Machine id of what `detect` thinks the input is, without fully decoding it. */
export interface Detection {
  /** Same values as Decoded.kind ("x402.payment-payload", "ap2.mandate-chain", ...) or "unknown". */
  kind: string;
  /** Header name the user pasted, lowercased, if any. */
  header?: string;
  /** How the value was encoded: "json", "base64-json", "sd-jwt", "jwt", "solana-tx", "auth-params", "http", "curl". */
  encoding?: string;
}

export function nowOf(opts?: DecodeOptions): number {
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
