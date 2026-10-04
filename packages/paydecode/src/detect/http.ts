// Parsing of pasted HTTP requests/responses and curl command lines into header/body pairs.
import { decodeString } from "./classify.js";
import type { Ctx } from "./classify.js";
import { decodeMppChallenge, decodeMppCredential, decodeMppReceipt } from "../mpp.js";
import { decodeSignatureInput } from "../tap.js";
import type { Decoded } from "../types.js";

// ---------------------------------------------------------------- HTTP / curl pastes

export const KNOWN_HEADERS =
  /^(x-payment-response|x-payment|payment-required|payment-signature|payment-response|payment-receipt|payment-authorization|www-authenticate|authorization|signature-input|signature|extension-responses)$/i;

export interface HttpPaste {
  headers: { name: string; value: string }[];
  body?: string;
  status?: string;
}

export function parseHttpPaste(input: string): HttpPaste | undefined {
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

export function decodeHeaderValue(name: string, value: string, ctx: Ctx): Decoded | undefined {
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
