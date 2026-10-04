// The Unrecognized result: explains what the input looked like when no decoder matched.
import { MAX_JSON_DEPTH, decodeBase64, isRecord, jsonTooDeep, tryJson, utf8 } from "../core/encoding.js";
import { field, flag, section, short } from "../core/format.js";
import { looksLikeJwt, looksLikeSdJwt } from "../crypto/sdjwt.js";
import type { Flag, Unrecognized } from "../types.js";

// ---------------------------------------------------------------- public

export function unrecognized(input: string, header?: string): Unrecognized {
  const text = input.trim();
  const sections = [];
  let summary: string;
  let raw: unknown = text;
  const flags: Flag[] = [];
  const j = tryJson(text);
  const bytes = j === undefined ? decodeBase64(text) : null;
  const bj = bytes ? tryJson(utf8(bytes)) : undefined;
  const deepText = j === undefined && /^[[{]/.test(text) ? text : bytes && j === undefined && bj === undefined ? utf8(bytes).trim() : "";
  if (/^[[{]/.test(deepText) && jsonTooDeep(deepText)) {
    summary = `This looks like JSON${deepText === text ? "" : " (base64-encoded)"} nested more than ${MAX_JSON_DEPTH} levels deep. No payment artifact nests that far, so it wasn't parsed.`;
    flags.push(flag("warn", "JSON_TOO_DEEP", `JSON nesting exceeds ${MAX_JSON_DEPTH} levels; not decoded.`));
  } else if (j !== undefined || bj !== undefined) {
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
    summary = `Not JSON, base64, a JWT/SD-JWT, or a known payment header${text.length > 0 ? ` (starts with "${short(text, 16, 0)}")` : ""}.`;
  }
  if (header) flags.push(flag("info", "HEADER_SEEN", `Pasted with header '${header}'.`));
  return { kind: "unknown", title: "Unrecognized input", summary, sections, flags, raw };
}
