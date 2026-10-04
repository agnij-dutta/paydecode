import { useState } from "react";

interface Props {
  value: string;
  display: string;
  title?: string;
  className?: string;
}

/** Click to copy the full value; shows the truncated display. */
export function Copyable({ value, display, title, className = "" }: Props) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      // Clipboard can be blocked (insecure context, permissions); say so instead of pretending it worked.
      setState("failed");
    }
    window.setTimeout(() => setState("idle"), 1200);
  };
  return (
    <button
      type="button"
      className={`copyable ${className}`}
      title={title ?? `Copy ${value}`}
      aria-label={`Copy ${value}`}
      onClick={() => void copy()}
    >
      <span>{display}</span>
      <span className="copy-hint" aria-live="polite">
        {state === "copied" ? "copied" : state === "failed" ? "copy failed" : "copy"}
      </span>
    </button>
  );
}
