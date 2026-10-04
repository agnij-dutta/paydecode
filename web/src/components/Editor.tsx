import { forwardRef, useRef, type ChangeEvent } from "react";
import { segmentInput } from "../lib/segments";

interface Props {
  value: string;
  onChange: (v: string) => void;
}

/** A textarea with a color-coded mirror behind it, so the raw input carries the same palette as the decoded view. */
export const Editor = forwardRef<HTMLTextAreaElement, Props>(function Editor({ value, onChange }, ref) {
  const mirror = useRef<HTMLPreElement>(null);
  const { segments } = segmentInput(value);

  return (
    <div className="editor">
      <pre className="editor-mirror" ref={mirror} aria-hidden="true">
        {segments.map((s, i) => (
          <span key={i} className={`seg seg-${s.tone}`}>
            {s.text}
          </span>
        ))}
        {"\n"}
        {!value && (
          <span className="editor-placeholder">
            Paste an x402 header, AP2 mandate, EIP-3009 authorization or Solana transaction.
            <br />
            <br />
            Full header lines like <code>PAYMENT-SIGNATURE: eyJ4...</code> work too.
          </span>
        )}
      </pre>
      <textarea
        ref={ref}
        className="editor-input"
        value={value}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        autoCorrect="off"
        aria-label="Payment artifact to decode"
        onChange={(e: ChangeEvent<HTMLTextAreaElement>) => onChange(e.target.value)}
        onScroll={(e) => {
          if (mirror.current) mirror.current.scrollTop = e.currentTarget.scrollTop;
        }}
      />
    </div>
  );
});
