// Public result types. The web app and other consumers code against these, so changes must stay additive.
export type FlagLevel = "danger" | "warn" | "info" | "ok";

/** A finding about the artifact, ranked by how much it should worry you. */
export interface Flag {
  level: FlagLevel;
  /** Stable machine id, e.g. "AUTH_EXPIRED". */
  code: string;
  message: string;
}

export interface Field {
  label: string;
  value: string;
  /** Optional human gloss, e.g. "≈ 2 hours from now". */
  note?: string;
  /** Hint for the UI: render as address / amount / time / hash / code. */
  kind?: "address" | "amount" | "time" | "hash" | "code" | "text";
}

export interface Section {
  title: string;
  fields: Field[];
}

export interface Decoded {
  /** Machine id of the format, e.g. "x402.payment-payload". */
  kind: string;
  /** Human title, e.g. "x402 payment (v2)". */
  title: string;
  /** One or two plain-English sentences: what this artifact authorizes. */
  summary: string;
  sections: Section[];
  flags: Flag[];
  /** The decoded JSON (or structure), for the raw view. */
  raw: unknown;
  /** Artifacts found inside this one (e.g. requirements inside a 402 body). */
  children?: Decoded[];
}

export interface DecodeOptions {
  /** Reference time in unix seconds. Defaults to now. */
  now?: number;
}

export interface Unrecognized {
  kind: "unknown";
  title: string;
  summary: string;
  sections: Section[];
  flags: Flag[];
  raw: unknown;
}
