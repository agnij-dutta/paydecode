import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { Editor } from "./components/Editor";
import { ResultView } from "./components/ResultView";
import type { Result } from "./lib/decoder";
import { EXAMPLES } from "./lib/examples";
import { segmentInput } from "./lib/segments";

const HASH_KEY = "i";
const PREF_KEY = "paydecode:url-sync";
const THEME_KEY = "paydecode:theme";

function readHash(): string {
  const h = window.location.hash.slice(1);
  if (!h) return "";
  const params = new URLSearchParams(h);
  return params.get(HASH_KEY) ?? "";
}

function writeHash(value: string) {
  const url = new URL(window.location.href);
  url.hash = value ? `${HASH_KEY}=${encodeURIComponent(value)}` : "";
  const next = value ? url.toString() : url.toString().replace(/#$/, "");
  window.history.replaceState(null, "", next);
}

function load(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}
function save(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* storage blocked */
  }
}

type Theme = "system" | "light" | "dark";

function useTheme() {
  const [theme, setTheme] = useState<Theme>(() => (load(THEME_KEY) as Theme) || "system");
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    save(THEME_KEY, theme);
  }, [theme]);
  const cycle = () => setTheme((t) => (t === "system" ? "dark" : t === "dark" ? "light" : "system"));
  return { theme, cycle };
}

// The decoder (and its crypto) loads as a separate chunk so the page paints first.
// It is still plain JavaScript running in this tab: no input ever leaves the browser.
interface DecoderApi {
  runDecode: (input: string, now?: number) => Result;
  buildBrokenExample: () => string;
}
let decoderApi: DecoderApi | null = null;
const decoderReady: Promise<DecoderApi> = Promise.all([import("./lib/decoder"), import("./lib/brokenExample")]).then(
  ([d, b]) => (decoderApi = { runDecode: d.runDecode, buildBrokenExample: b.buildBrokenExample }),
);

// The broken example is signed in-page (fresh validity window), then reused until clicked again.
const generated: Record<string, string> = {};

function exampleText(id: string) {
  const ex = EXAMPLES.find((e) => e.id === id);
  if (!ex) return "";
  if (ex.id === "broken-domain" && decoderApi) {
    try {
      return (generated[id] ??= decoderApi.buildBrokenExample());
    } catch {
      /* fall back to the static, unsigned-for-the-wrong-domain variant */
    }
  }
  return ex.header ? `${ex.header}: ${ex.value}` : ex.value;
}

export default function App() {
  const [input, setInput] = useState<string>(() => readHash());
  const [urlSync, setUrlSync] = useState<boolean>(() => load(PREF_KEY) !== "off");
  const [linkState, setLinkState] = useState<"idle" | "copied" | "failed">("idle");
  const [now, setNow] = useState(() => Date.now() / 1000);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const { theme, cycle } = useTheme();
  const deferred = useDeferredValue(input);
  const [api, setApi] = useState<DecoderApi | null>(decoderApi);

  useEffect(() => {
    if (!api) void decoderReady.then(setApi);
  }, [api]);

  // Keep relative times honest while the page is open.
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now() / 1000), 30_000);
    return () => window.clearInterval(t);
  }, []);

  // Cmd/Ctrl+K focuses the input.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Back/forward or a pasted link with a new hash.
  useEffect(() => {
    const onHash = () => setInput(readHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Mirror input into the URL hash (never the query string: hashes are not sent to servers).
  useEffect(() => {
    const t = window.setTimeout(() => writeHash(urlSync ? input.trim() : ""), 250);
    return () => window.clearTimeout(t);
  }, [input, urlSync]);

  const result = useMemo<{ ok: true; value: Result } | { ok: false; error: string } | null>(() => {
    if (!deferred.trim() || !api) return null;
    try {
      return { ok: true, value: api.runDecode(deferred, now) };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }, [deferred, now, api]);

  const seg = useMemo(() => segmentInput(deferred), [deferred]);
  const activeExample = EXAMPLES.find((e) => exampleText(e.id) === input.trim())?.id;
  const recognized = result?.ok && result.value.kind !== "unknown";
  const chainMode = seg.mode === "chain";
  const children = result?.ok && "children" in result.value ? (result.value.children ?? []) : [];

  const hopTitles = result?.ok ? result.value.sections.map((s) => s.title).filter((t) => /^Hop \d+/.test(t)) : [];
  const legend = chainMode
    ? seg.legend.map((l, i) => ({
        ...l,
        label: hopTitles[i] ? hopTitles[i].replace(/:\s*/, " · ") : children[i]?.title ? `Hop ${i + 1} · ${children[i].title}` : l.label,
      }))
    : seg.legend;

  const toggleSync = useCallback(() => {
    setUrlSync((v) => {
      save(PREF_KEY, v ? "off" : "on");
      return !v;
    });
  }, []);

  const copyLink = async () => {
    writeHash(input.trim());
    try {
      await navigator.clipboard.writeText(window.location.href);
      setLinkState("copied");
    } catch {
      // Clipboard blocked: the URL bar already holds the link, so point there.
      setLinkState("failed");
    }
    window.setTimeout(() => setLinkState("idle"), 1400);
  };

  return (
    <div className="shell">
      <header className="topbar">
        <h1 className="sr-only">paydecode: decode agent payment artifacts</h1>
        <a className="brand" href="/" aria-label="paydecode home">
          <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
            <rect x="2.5" y="4.5" width="19" height="15" rx="2" fill="none" stroke="currentColor" strokeWidth="1.6" />
            <path d="M6 10h4M6 14h7M15 10h3" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" />
          </svg>
          <span>paydecode</span>
        </a>
        <p className="tagline">Paste an agent payment. Read what it authorizes.</p>
        <div className="topbar-actions">
          <span className="local-badge" title="Decoding runs in this tab. No request is made with your input.">
            <svg viewBox="0 0 16 16" width="13" height="13" aria-hidden="true">
              <rect x="3" y="7" width="10" height="7" rx="1.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
              <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" fill="none" stroke="currentColor" strokeWidth="1.4" />
            </svg>
            Decoded locally · nothing is uploaded
          </span>
          <button
            type="button"
            className="ghost"
            onClick={cycle}
            aria-label={`Color theme: ${theme === "system" ? "Auto" : theme === "dark" ? "Dark" : "Light"}`}
            title="Cycle color theme: Auto, Dark, Light"
          >
            {theme === "system" ? "Auto" : theme === "dark" ? "Dark" : "Light"}
          </button>
        </div>
      </header>

      <nav className="examples" aria-label="Examples">
        <span className="examples-label">Try</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex.id}
            type="button"
            className={`example ${ex.broken ? "example-broken" : ""} ${activeExample === ex.id ? "is-active" : ""}`}
            aria-pressed={activeExample === ex.id}
            onClick={() => {
              if (ex.id === "broken-domain") delete generated[ex.id];
              setInput(exampleText(ex.id));
            }}
          >
            {ex.label}
          </button>
        ))}
      </nav>

      <main className="panes">
        <section className="pane pane-input" aria-labelledby="input-heading">
          <h2 id="input-heading" className="sr-only">
            Input
          </h2>
          <div className="pane-head">
            <div className="detect" aria-live="polite">
              {result === null ? (
                <span className="chip chip-idle">Waiting for input</span>
              ) : recognized && result.ok ? (
                <span className="chip chip-on">
                  <i aria-hidden="true" />
                  {result.value.title}
                </span>
              ) : (
                <span className="chip chip-off">Not recognized</span>
              )}
            </div>
            <kbd className="kbd" title="Focus the input">
              {navigator.platform.toLowerCase().includes("mac") ? "⌘" : "Ctrl"} K
            </kbd>
          </div>
          <Editor ref={inputRef} value={input} onChange={setInput} />
          <div className="pane-foot">
            {legend.length > 0 ? (
              <ul className="legend" aria-label="Input color key">
                {legend.map((l) => (
                  <li key={l.tone} className={`tone-${l.tone}`}>
                    <i aria-hidden="true" />
                    {l.label}
                  </li>
                ))}
              </ul>
            ) : (
              <span className="legend-empty">{input ? `${input.length.toLocaleString()} chars` : ""}</span>
            )}
            <div className="url-ctl">
              <label className="switch">
                <input type="checkbox" checked={urlSync} onChange={toggleSync} />
                <span>Keep input in URL</span>
              </label>
              {urlSync && input.trim() && (
                <button type="button" className="ghost small" onClick={() => void copyLink()}>
                  {linkState === "copied" ? "Link copied" : linkState === "failed" ? "Copy blocked, use the address bar" : "Copy link"}
                </button>
              )}
            </div>
          </div>
        </section>

        <section className="pane pane-output" aria-labelledby="output-heading">
          <h2 id="output-heading" className="sr-only">
            Decoded result
          </h2>
          {result === null ? (
            <div className="empty">
              <p className="empty-title">Nothing decoded yet.</p>
              <p>
                Paste a header value, a full header line, a JWT or JSON on the left, or pick an example above. The one marked Broken shows
                how a single wrong EIP-712 domain name makes a USDC payment fail to verify.
              </p>
              <p className="empty-formats">
                Reads x402 v1 and v2 (challenges, payments, receipts), AP2 mandates and SD-JWT delegation chains, EIP-3009 authorizations,
                Permit2 witnesses and Solana payment transactions.
              </p>
            </div>
          ) : result.ok ? (
            <ResultView result={result.value} now={now} chainMode={chainMode} />
          ) : (
            <div className="empty">
              <p className="empty-title">The decoder hit an error on this input.</p>
              <p className="mono">{result.error}</p>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
