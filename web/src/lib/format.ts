const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31536000],
  ["month", 2592000],
  ["week", 604800],
  ["day", 86400],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];

function relative(deltaSeconds: number): string {
  const abs = Math.abs(deltaSeconds);
  for (const [unit, secs] of UNITS) {
    if (abs >= secs || unit === "second") {
      return rtf.format(Math.round(deltaSeconds / secs), unit);
    }
  }
  return "";
}

const EXPIRY = /(valid ?before|valid until|exp|deadline|not.?after|expir)/i;
const START = /(valid ?after|not.?before|starts)/i;

export interface TimeGloss {
  text: string;
  tone: "past" | "future" | "expired" | "pending";
}

/**
 * Relative gloss for a time field, from the library's Field.unixSeconds (never by re-parsing the
 * display string). Fields without unixSeconds keep the library's own note instead.
 */
export function timeGloss(label: string, unixSeconds: number | undefined, now = Date.now() / 1000): TimeGloss | null {
  if (unixSeconds === undefined) return null;
  const t = unixSeconds;
  // Far-future values (e.g. a uint256-max deadline) read better as the library's own note.
  if (t > 4102444800) return null;
  const delta = t - now;
  const rel = relative(delta);
  if (EXPIRY.test(label)) {
    return delta < 0 ? { text: `expired ${rel}`, tone: "expired" } : { text: `expires ${rel}`, tone: "future" };
  }
  if (START.test(label) && delta > 0) return { text: `not valid until ${rel}`, tone: "pending" };
  return { text: rel, tone: delta < 0 ? "past" : "future" };
}

export function truncateMiddle(s: string, head = 6, tail = 4): string {
  if (s.length <= head + tail + 3) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

/** JSON.stringify that survives bigint and byte arrays. */
export function safeJson(value: unknown): string {
  try {
    return JSON.stringify(
      value,
      (_key, v: unknown) => {
        if (typeof v === "bigint") return v.toString();
        if (v instanceof Uint8Array) return "0x" + Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("");
        return v;
      },
      2,
    );
  } catch {
    return String(value);
  }
}
