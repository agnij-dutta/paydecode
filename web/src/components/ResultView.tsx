import type { Decoded, Flag, FlagLevel, Result } from "../lib/decoder";
import { findNetwork, type NetworkInfo } from "../lib/networks";
import { toneForSection } from "../lib/segments";
import { FieldRow } from "./FieldRow";
import { RawJson } from "./RawJson";

const ORDER: Record<FlagLevel, number> = { danger: 0, warn: 1, info: 2, ok: 3 };
const LEVEL_LABEL: Record<FlagLevel, string> = { danger: "Danger", warn: "Warning", info: "Note", ok: "Check passed" };

export function sortFlags(flags: Flag[]) {
  return [...flags].sort((a, b) => ORDER[a.level] - ORDER[b.level]);
}

/** Set amounts, addresses and hashes inside the summary sentence in the data face. */
function Summary({ text }: { text: string }) {
  const parts = text.split(/(0x[0-9a-fA-F]{6,}…?[0-9a-fA-F]*|\b\d[\d,]*(?:\.\d+)?\s?(?:USDC|USD|EUR|SOL|ETH|USDT|EURC)\b|\$\d[\d,]*(?:\.\d+)?)/g);
  return (
    <p className="summary">
      {parts.map((p, i) => (i % 2 === 1 ? <span key={i} className="summary-data">{p}</span> : p))}
    </p>
  );
}

function Tally({ flags }: { flags: Flag[] }) {
  const n = (l: FlagLevel) => flags.filter((f) => f.level === l).length;
  const items: [FlagLevel, number, string][] = [
    ["danger", n("danger"), n("danger") === 1 ? "danger" : "dangers"],
    ["warn", n("warn"), n("warn") === 1 ? "warning" : "warnings"],
    ["ok", n("ok"), n("ok") === 1 ? "check passed" : "checks passed"],
  ];
  const shown = items.filter(([, c]) => c > 0);
  if (!shown.length) return null;
  return (
    <div className="tally">
      {shown.map(([l, c, word]) => (
        <span key={l} className={`tally-item lvl-${l}`}>
          <i aria-hidden="true" />
          {c} {word}
        </span>
      ))}
    </div>
  );
}

function FlagList({ flags }: { flags: Flag[] }) {
  if (!flags.length) return null;
  return (
    <ul className="flags" aria-label="Findings">
      {sortFlags(flags).map((f, i) => (
        <li key={`${f.code}-${i}`} className={`flag lvl-${f.level}`}>
          <span className="flag-level">{LEVEL_LABEL[f.level]}</span>
          <span className="flag-msg">{f.message}</span>
          <code className="flag-code">{f.code}</code>
        </li>
      ))}
    </ul>
  );
}

interface Props {
  result: Result;
  now: number;
  depth?: number;
  /** Palette slot tying this card to a colored segment of the input. */
  tone?: number | null;
  inheritedNet?: NetworkInfo | null;
  chainMode?: boolean;
}

export function ResultView({ result, now, depth = 0, tone = null, inheritedNet = null, chainMode = false }: Props) {
  const values = result.sections.flatMap((s) => s.fields.map((f) => f.value));
  const net = findNetwork(values, result.raw) ?? inheritedNet;
  const children = "children" in result ? ((result as Decoded).children ?? []) : [];
  const nested = depth > 0;

  return (
    <article className={`result ${nested ? "result-nested" : ""} ${tone !== null ? `tone-${tone}` : ""}`}>
      {nested ? (
        <header className="nested-head">
          <h3>{result.title}</h3>
          <code>{result.kind}</code>
        </header>
      ) : null}
      <Summary text={result.summary} />
      {!nested && <Tally flags={result.flags} />}
      <FlagList flags={result.flags} />

      {result.sections.map((s, i) => {
        const st = chainMode ? null : toneForSection(s.title);
        return (
          <section key={`${s.title}-${i}`} className={`fields ${st !== null ? `tone-${st}` : ""}`}>
            <h4>{s.title}</h4>
            <dl>
              {s.fields.map((f, j) => (
                <FieldRow key={`${f.label}-${j}`} field={f} net={net} now={now} />
              ))}
            </dl>
          </section>
        );
      })}

      {children.length > 0 && (
        <div className="children">
          {children.map((c, i) => (
            <ResultView
              key={i}
              result={c}
              now={now}
              depth={depth + 1}
              tone={chainMode && depth === 0 ? i % 4 : null}
              inheritedNet={net}
            />
          ))}
        </div>
      )}

      {!nested && <RawJson value={result.raw} />}
    </article>
  );
}
