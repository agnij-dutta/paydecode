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

export function relative(deltaSeconds: number): string {
  const abs = Math.abs(deltaSeconds);
  for (const [unit, secs] of UNITS) {
    if (abs >= secs || unit === "second") {
      return rtf.format(Math.round(deltaSeconds / secs), unit);
    }
  }
  return "";
}

/** Pull a unix-seconds timestamp out of a field value (raw seconds, ms, or ISO date). */
export function parseTime(value: string): number | null {
  const iso = value.match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?/);
  if (iso) {
    const t = Date.parse(iso[0]);
    if (!Number.isNaN(t)) return Math.floor(t / 1000);
  }
  const num = value.match(/\b\d{9,13}\b/);
  if (num) {
    const n = Number(num[0]);
    return num[0].length >= 13 ? Math.floor(n / 1000) : n;
  }
  return null;
}

const EXPIRY = /(valid ?before|valid until|exp|deadline|not.?after|expir)/i;
const START = /(valid ?after|not.?before|starts)/i;

export interface TimeGloss {
  text: string;
  tone: "past" | "future" | "expired" | "pending";
}

export function timeGloss(label: string, value: string, now = Date.now() / 1000): TimeGloss | null {
  const t = parseTime(value);
  if (t === null) return null;
  // Ignore obviously non-timestamp numbers (before 2001 or after 2100).
  if (t < 978307200 || t > 4102444800) return null;
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
      (_k, v) => {
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
