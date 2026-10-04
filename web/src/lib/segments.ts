/**
 * Splits the raw input into colored segments, jwt.io style, so the textarea
 * overlay and the decoded view share one color language.
 */
export interface Segment {
  text: string;
  /** Palette slot 0..3, "name" for a header name, "sep" for delimiters, "plain" otherwise. */
  tone: number | "name" | "sep" | "plain";
}

export interface SegmentInfo {
  segments: Segment[];
  mode: "chain" | "jwt" | "header" | "plain";
  /** Legend entries keyed by palette slot. */
  legend: { tone: number; label: string }[];
}

const HEADER_RE = /^(\s*)([A-Za-z][A-Za-z0-9-]*)(\s*:\s*)/;
const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(~.*)?$/s;

function splitJwt(token: string, tone: (part: number) => number): Segment[] {
  const out: Segment[] = [];
  let part = 0;
  let buf = "";
  const flush = () => {
    if (buf) out.push({ text: buf, tone: tone(part) });
    buf = "";
  };
  for (const ch of token) {
    if (ch === "." && part < 2) {
      flush();
      out.push({ text: ch, tone: "sep" });
      part++;
    } else if (ch === "~") {
      flush();
      out.push({ text: ch, tone: "sep" });
      part = 3;
    } else {
      buf += ch;
    }
  }
  flush();
  return out;
}

export function segmentInput(input: string): SegmentInfo {
  const segments: Segment[] = [];
  let rest = input;
  const header = rest.match(HEADER_RE);
  // Only treat "Name: value" as a header when the value is not JSON (avoid eating `{"a": 1}`).
  if (header && !rest.trimStart().startsWith("{")) {
    segments.push({ text: header[1], tone: "plain" }, { text: header[2], tone: "name" }, { text: header[3], tone: "sep" });
    rest = rest.slice(header[0].length);
  }
  const body = rest.trim();

  if (body.includes("~~")) {
    const hops = rest.split("~~");
    hops.forEach((hop, i) => {
      if (i > 0) segments.push({ text: "~~", tone: "sep" });
      segments.push(...splitJwt(hop, () => i % 4));
    });
    return {
      segments,
      mode: "chain",
      legend: hops.slice(0, 4).map((_, i) => ({ tone: i, label: `Hop ${i + 1}` })),
    };
  }

  if (JWT_RE.test(body)) {
    segments.push(...splitJwt(rest, (p) => p));
    const legend = [
      { tone: 0, label: "Header" },
      { tone: 1, label: "Payload" },
      { tone: 2, label: "Signature" },
    ];
    if (body.includes("~")) legend.push({ tone: 3, label: "Disclosures" });
    return { segments, mode: "jwt", legend };
  }

  segments.push({ text: rest, tone: header ? 1 : "plain" });
  return {
    segments,
    mode: header ? "header" : "plain",
    legend: header ? [{ tone: 1, label: `${header[2]} value` }] : [],
  };
}

/** Map a decoded section title onto a JWT palette slot, if it names a JWT part. */
export function toneForSection(title: string): number | null {
  if (/header/i.test(title)) return 0;
  if (/payload|claims/i.test(title)) return 1;
  if (/signature/i.test(title)) return 2;
  if (/disclos/i.test(title)) return 3;
  return null;
}

/** In a `~~` chain, sections and rows named "Hop N" take hop N's palette slot. */
export function toneForHop(title: string): number | null {
  const m = title.match(/^Hop (\d+)/);
  return m ? (Number(m[1]) - 1) % 4 : null;
}
