import type { ReactElement } from "react";
import { safeJson } from "../lib/format";

const TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

function highlight(json: string) {
  const out: (string | ReactElement)[] = [];
  let last = 0;
  let i = 0;
  for (const m of json.matchAll(TOKEN)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push(json.slice(last, idx));
    if (m[1]) {
      out.push(
        <span key={i++} className={m[2] ? "j-key" : "j-str"}>
          {m[1]}
        </span>,
      );
      if (m[2]) out.push(m[2]);
    } else if (m[3]) out.push(<span key={i++} className="j-lit">{m[3]}</span>);
    else out.push(<span key={i++} className="j-num">{m[4]}</span>);
    last = idx + m[0].length;
  }
  out.push(json.slice(last));
  return out;
}

export function RawJson({ value }: { value: unknown }) {
  const json = safeJson(value);
  return (
    <details className="raw">
      <summary>Raw decoded JSON</summary>
      <pre>{highlight(json)}</pre>
    </details>
  );
}
