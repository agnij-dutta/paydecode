import type { Field } from "../lib/decoder";
import { explorerLink, isBase58, isEvmAddress, type NetworkInfo } from "../lib/networks";
import { timeGloss, truncateMiddle } from "../lib/format";
import { Copyable } from "./Copyable";

function ExplorerLink({ href, net }: { href: string; net: NetworkInfo }) {
  return (
    <a className="explorer" href={href} target="_blank" rel="noreferrer noopener" title={`Open on ${net.name} explorer`}>
      explorer
    </a>
  );
}

function looksLikeAddress(v: string) {
  return isEvmAddress(v) || isBase58(v);
}

function Value({ field, net, now }: { field: Field; net: NetworkInfo | null; now: number }) {
  const v = field.value;
  switch (field.kind) {
    case "address": {
      if (!looksLikeAddress(v)) return <span className="v-text">{v}</span>;
      const href = explorerLink(net, v, "address");
      return (
        <span className="v-line">
          <Copyable value={v} display={truncateMiddle(v, 8, 6)} className="v-mono" />
          {href && net && <ExplorerLink href={href} net={net} />}
        </span>
      );
    }
    case "hash": {
      const isTx = /tx|transaction|signature/i.test(field.label);
      const href = isTx ? explorerLink(net, v, "tx") : null;
      if (v.length <= 24) return <span className="v-mono">{v}</span>;
      return (
        <span className="v-line">
          <Copyable value={v} display={truncateMiddle(v, 10, 8)} className="v-mono" />
          {href && net && <ExplorerLink href={href} net={net} />}
        </span>
      );
    }
    case "amount":
      return <span className="v-mono v-amount">{v}</span>;
    case "time": {
      const g = timeGloss(field.label, field.unixSeconds, now);
      return (
        <span className="v-line">
          <span className="v-mono">{v}</span>
          {g && <span className={`gloss gloss-${g.tone}`}>{g.text}</span>}
        </span>
      );
    }
    case "code":
      return <code className="v-code">{v}</code>;
    default:
      return <span className="v-text">{v}</span>;
  }
}

interface RowProps {
  field: Field;
  net: NetworkInfo | null;
  now: number;
  /** Palette slot when this row belongs to a colored input segment (an AP2 hop). */
  tone?: number | null;
}

export function FieldRow({ field, net, now, tone = null }: RowProps) {
  const showNote = field.note && !(field.kind === "time" && timeGloss(field.label, field.unixSeconds, now));
  return (
    <div className="row">
      <dt className={tone !== null ? `tone-${tone} dt-tone` : undefined}>{field.label}</dt>
      <dd>
        <Value field={field} net={net} now={now} />
        {showNote && <span className="note">{field.note}</span>}
      </dd>
    </div>
  );
}
