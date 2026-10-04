// Formatting helpers shared by every decoder. Plain English, no em dashes.
import type { Field, Flag, FlagLevel, Section } from "./types.js";

/**
 * Render an untrusted JSON value as text. Strings pass through; objects become JSON
 * instead of "[object Object]", because decoded artifacts can put anything in any field.
 */
export function asText(value: unknown, fallback: unknown = ""): string {
  if (value === undefined || value === null) return fallback === undefined || fallback === null ? "" : asText(fallback);
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
}

/** 0x857b06519E91e3A54538791bDbb0E22373e36b66 -> 0x857b…6b66 */
export function short(s: unknown, head = 6, tail = 4): string {
  const v = asText(s, "");
  if (v.length <= head + tail + 1) return v;
  return `${v.slice(0, head)}…${v.slice(-tail)}`;
}

function groupThousands(int: string): string {
  return int.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** Format an atomic integer amount with `decimals`. 10000 @ 6 -> "0.01". */
export function formatUnits(value: unknown, decimals: number, minFraction = 2): string {
  let v: bigint;
  try {
    v = BigInt(asText(value));
  } catch {
    return asText(value);
  }
  const neg = v < 0n;
  if (neg) v = -v;
  const base = 10n ** BigInt(decimals);
  const int = (v / base).toString();
  let frac = decimals > 0 ? (v % base).toString().padStart(decimals, "0").replace(/0+$/, "") : "";
  if (frac.length < minFraction && decimals >= minFraction) frac = frac.padEnd(minFraction, "0");
  return (neg ? "-" : "") + groupThousands(int) + (frac ? "." + frac : "");
}

const ZERO_DECIMAL = new Set(["JPY", "KRW", "VND", "CLP", "ISK", "UGX", "XAF", "XOF", "PYG", "RWF"]);
const SYMBOL: Record<string, string> = { USD: "$", EUR: "€", GBP: "£", JPY: "¥", INR: "₹", CAD: "CA$", AUD: "A$" };

/** Fiat minor units -> "$200.00 USD". */
export function formatMinor(amount: unknown, currency: unknown): string {
  const cur = asText(currency, "").toUpperCase();
  const decimals = ZERO_DECIMAL.has(cur) ? 0 : 2;
  const num = formatUnits(amount, decimals);
  const sym = SYMBOL[cur] ?? "";
  return `${sym}${num}${cur ? " " + cur : ""}`;
}

/** Fiat major units (float) -> "$12.50 USD". */
export function formatMajor(amount: unknown, currency: unknown): string {
  const cur = asText(currency, "").toUpperCase();
  const n = Number(amount);
  const num = Number.isFinite(n) ? n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 8 }) : asText(amount);
  return `${SYMBOL[cur] ?? ""}${num}${cur ? " " + cur : ""}`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function toUnix(v: unknown): number | undefined {
  if (v === undefined || v === null || v === "") return undefined;
  if (typeof v === "number" && Number.isFinite(v)) return v > 1e12 ? Math.floor(v / 1000) : v;
  const s = asText(v).trim();
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    return n > 1e12 ? Math.floor(n / 1000) : n;
  }
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? undefined : Math.floor(ms / 1000);
}

/** "27 Feb 2025" */
export function formatDay(unix: number): string {
  const d = new Date(unix * 1000);
  if (Number.isNaN(d.getTime())) return asText(unix);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

/** "27 Feb 2025, 16:01:29 UTC" */
export function formatTime(unix: number): string {
  const d = new Date(unix * 1000);
  if (Number.isNaN(d.getTime()) || unix > 253402300799) return `${unix} (far future)`;
  const p = (n: number) => asText(n).padStart(2, "0");
  return `${formatDay(unix)}, ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`;
}

const UNITS: [number, string][] = [
  [365 * 86400, "year"],
  [30 * 86400, "month"],
  [86400, "day"],
  [3600, "hour"],
  [60, "minute"],
  [1, "second"],
];

/** 65 -> "65 seconds", 7260 -> "2 hours 1 minute". */
export function duration(seconds: number): string {
  let s = Math.abs(Math.round(seconds));
  if (s < 120) return `${s} second${s === 1 ? "" : "s"}`;
  const parts: string[] = [];
  for (const [size, name] of UNITS) {
    if (s >= size && parts.length < 2) {
      const n = Math.floor(s / size);
      s -= n * size;
      parts.push(`${n} ${name}${n === 1 ? "" : "s"}`);
    } else if (parts.length) break;
  }
  return parts.join(" ") || "0 seconds";
}

/** "in 2 hours" / "3 days ago" */
export function relative(unix: number, now: number): string {
  const d = unix - now;
  if (Math.abs(d) < 5) return "right now";
  return d > 0 ? `in ${duration(d)}` : `${duration(d)} ago`;
}

export const field = (label: string, value: unknown, kind?: Field["kind"], note?: string): Field => {
  const f: Field = { label, value: typeof value === "string" ? value : (JSON.stringify(value) ?? asText(value)) };
  if (kind) f.kind = kind;
  if (note) f.note = note;
  return f;
};

export const timeField = (label: string, unix: number | undefined, now: number, raw?: unknown): Field =>
  unix === undefined
    ? field(label, asText(raw, "not set"), "time")
    : unix === 0
      ? field(label, "0 (no start time)", "time")
      : field(label, formatTime(unix), "time", `${relative(unix, now)}; raw ${asText(raw, unix)}`);

export const flag = (level: FlagLevel, code: string, message: string): Flag => ({ level, code, message });

const ORDER: Record<FlagLevel, number> = { danger: 0, warn: 1, info: 2, ok: 3 };

export function sortFlags(flags: Flag[]): Flag[] {
  const seen = new Set<string>();
  return flags
    .filter((f) => {
      const k = f.code + "|" + f.message;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .sort((a, b) => ORDER[a.level] - ORDER[b.level]);
}

export const section = (title: string, fields: Field[]): Section => ({ title, fields: fields.filter(Boolean) });

export function plural(n: number, word: string, pluralWord = word + "s"): string {
  return `${n} ${n === 1 ? word : pluralWord}`;
}

export function listJoin(items: string[], conj = "and"): string {
  if (items.length <= 1) return items.join("");
  if (items.length === 2) return `${items[0]} ${conj} ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, ${conj} ${items[items.length - 1]}`;
}

/** Ensure a sentence ends with a period. */
export const sentence = (s: string) => (/[.!?]$/.test(s.trim()) ? s.trim() : s.trim() + ".");
