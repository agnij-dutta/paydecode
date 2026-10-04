import { decode, type Decoded, type Unrecognized } from "paydecode";
export type { Decoded, Unrecognized, Field, Flag, FlagLevel, Section } from "paydecode";

export type Result = Decoded | Unrecognized;

/** Everything happens in this tab: decode() is pure and makes no network calls. */
export function runDecode(input: string, now?: number): Result {
  return decode(input, now === undefined ? undefined : { now: Math.floor(now) });
}
