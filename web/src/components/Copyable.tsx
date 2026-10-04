import { useState } from "react";

interface Props {
  value: string;
  display: string;
  title?: string;
  className?: string;
}

/** Click to copy the full value; shows the truncated display. */
export function Copyable({ value, display, title, className = "" }: Props) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className={`copyable ${className}`}
      title={title ?? `Copy ${value}`}
      aria-label={`Copy ${value}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        } catch {
          /* clipboard unavailable */
        }
      }}
    >
      <span>{display}</span>
      <span className="copy-hint" aria-live="polite">
        {copied ? "copied" : "copy"}
      </span>
    </button>
  );
}
