#!/usr/bin/env node
// paydecode CLI: decode an agent-payment artifact in the terminal.
import { readFileSync, existsSync, statSync } from "node:fs";
import process from "node:process";
import { decode } from "./index.js";
import type { Decoded, Unrecognized, Flag } from "./types.js";

const HELP = `paydecode: jwt.io for agent payments

Usage
  paydecode <blob>            decode a header value, JSON, SD-JWT, base64 tx...
  paydecode <file>            decode the contents of a file
  echo <blob> | paydecode     read from stdin

Options
  --json         print the decoded result as JSON
  --now <unix>   evaluate expiry against this unix time instead of now
  --no-color     disable ANSI colors (also honors NO_COLOR)
  --strict       exit with code 3 if any DANGER flag is raised
  -h, --help     show this help

Examples
  paydecode "X-PAYMENT: eyJ4NDAyVmVyc2lvbiI6MSwic2NoZW1lIjoiZXhhY3QiLCJu..."
  curl -si https://api.example.com/paid | paydecode
`;

interface Args {
  json: boolean;
  now?: number;
  color: boolean;
  input?: string;
  help: boolean;
  strict: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { json: false, color: !process.env.NO_COLOR && !!process.stdout.isTTY, help: false, strict: false };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === "--json") a.json = true;
    else if (x === "--no-color") a.color = false;
    else if (x === "--color") a.color = true;
    else if (x === "--strict") a.strict = true;
    else if (x === "-h" || x === "--help") a.help = true;
    else if (x === "--now") {
      const v = Number(argv[++i]);
      if (!Number.isFinite(v)) throw new Error("--now needs a unix timestamp in seconds");
      a.now = v;
    } else if (x.startsWith("--now=")) a.now = Number(x.slice(6));
    else rest.push(x);
  }
  if (rest.length) a.input = rest.join(" ");
  return a;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function makeStyle(on: boolean) {
  const w =
    (code: string, end = "0") =>
    (s: string) =>
      on ? `\x1b[${code}m${s}\x1b[${end}m` : s;
  return {
    bold: w("1", "22"),
    dim: w("2", "22"),
    red: w("31", "39"),
    green: w("32", "39"),
    yellow: w("33", "39"),
    cyan: w("36", "39"),
    badge: (level: Flag["level"]) => {
      const label = { danger: " DANGER ", warn: " WARN   ", info: " INFO   ", ok: " OK     " }[level];
      if (!on) return `[${label.trim()}]`.padEnd(9);
      const bg = { danger: "41;97", warn: "43;30", info: "46;30", ok: "42;30" }[level];
      return `\x1b[${bg}m${label}\x1b[0m`;
    },
  };
}

function wrap(text: string, width: number, indent: string): string {
  const out: string[] = [];
  for (const para of text.split("\n")) {
    let line = "";
    for (const word of para.split(/\s+/)) {
      if (!word) continue;
      if (line && (line + " " + word).length > width) {
        out.push(indent + line);
        line = word;
      } else line = line ? line + " " + word : word;
    }
    out.push(indent + line);
  }
  return out.join("\n");
}

function render(d: Decoded | Unrecognized, color: boolean, depth = 0): string {
  const s = makeStyle(color);
  const pad = "  ".repeat(depth);
  const width = Math.max(40, Math.min(process.stdout.columns || 100, 110) - pad.length - 4);
  const lines: string[] = [];
  lines.push(`${pad}${s.bold(d.title)}  ${s.dim(d.kind)}`);
  lines.push("");
  lines.push(wrap(d.summary, width, pad + "  "));
  if (d.flags.length) {
    lines.push("");
    for (const f of d.flags) {
      const colorFn = { danger: s.red, warn: s.yellow, info: s.cyan, ok: s.green }[f.level];
      const body = wrap(f.message, width - 10, pad + "           ").trimStart();
      lines.push(`${pad}  ${s.badge(f.level)} ${colorFn(body)} ${s.dim(f.code)}`);
    }
  }
  for (const sec of d.sections) {
    if (!sec.fields.length) continue;
    lines.push("");
    lines.push(`${pad}  ${s.bold(sec.title)}`);
    const lw = Math.min(28, Math.max(...sec.fields.map((f) => f.label.length)));
    for (const f of sec.fields) {
      const v = f.value.length > 600 ? f.value.slice(0, 600) + "…" : f.value;
      lines.push(`${pad}    ${s.dim(f.label.padEnd(lw))}  ${v}${f.note ? "  " + s.dim(`(${f.note})`) : ""}`);
    }
  }
  const kids = "children" in d && d.children ? d.children : [];
  for (const c of kids) {
    lines.push("");
    lines.push(`${pad}  ${s.dim("contains:")}`);
    lines.push(render(c, color, depth + 1));
  }
  return lines.join("\n");
}

function hasDanger(d: Decoded | Unrecognized): boolean {
  return d.flags.some((f) => f.level === "danger") || ("children" in d && !!d.children?.some(hasDanger));
}

async function main() {
  let args: Args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`paydecode: ${(e as Error).message}\n`);
    process.exit(2);
  }
  if (args.help) {
    process.stdout.write(HELP);
    return;
  }
  let input = args.input;
  if (input === "-" || (input === undefined && !process.stdin.isTTY)) input = await readStdin();
  else if (input !== undefined && input.length < 4096 && !input.includes("\n")) {
    const p = input.startsWith("@") ? input.slice(1) : input;
    try {
      if (existsSync(p) && statSync(p).isFile()) input = readFileSync(p, "utf8");
    } catch {
      /* not a file */
    }
  }
  if (input === undefined || !input.trim()) {
    process.stdout.write(HELP);
    process.exit(input === undefined ? 0 : 1);
  }
  const d = decode(input, args.now !== undefined ? { now: args.now } : undefined);
  if (args.json) process.stdout.write(JSON.stringify(d, null, 2) + "\n");
  else process.stdout.write(render(d, args.color) + "\n");
  process.exitCode = d.kind === "unknown" ? 1 : args.strict && hasDanger(d) ? 3 : 0;
}

main().catch((e) => {
  process.stderr.write(`paydecode: ${(e as Error).stack ?? e}\n`);
  process.exit(2);
});
