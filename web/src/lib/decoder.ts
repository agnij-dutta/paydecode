// TEMPORARY stub: the real decoder lives in packages/paydecode and is swapped in once it builds.
import type { Decoded, Unrecognized } from "../../../packages/paydecode/src/types.ts";
export type { Decoded, Unrecognized, Field, Flag, FlagLevel, Section } from "../../../packages/paydecode/src/types.ts";

export type Result = Decoded | Unrecognized;

export function runDecode(input: string): Result {
  const body = input.replace(/^\s*[A-Za-z0-9-]+\s*:\s*/, "").trim();
  let raw: unknown = body;
  try {
    raw = JSON.parse(atob(body));
  } catch {
    /* not base64 json */
  }
  return {
    kind: "unknown",
    title: "Stub decoder",
    summary: "The paydecode library is still being built. This is placeholder output.",
    sections: [{ title: "Input", fields: [{ label: "Length", value: String(body.length) }] }],
    flags: [{ level: "info", code: "STUB", message: "Stub decoder in use." }],
    raw,
  };
}
