import { describe, it, expect } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { FIX } from "./helpers.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const FIXTURE = fileURLToPath(new URL("./fixtures/ap2-x402-bundle.json", import.meta.url));
const run = (args: string[], input?: string) =>
  spawnSync(process.execPath, [CLI, ...args], { input, encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });

describe.skipIf(!existsSync(CLI))("CLI (built dist)", () => {
  it("decodes a header argument", () => {
    const r = run(["--now", "1740672100", `PAYMENT-SIGNATURE: ${FIX.x402_v2_http["PAYMENT-SIGNATURE"][0]}`]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Authorizes 0x857b…6b66 to pay 0.01 USDC on Base Sepolia to 0x2096…287C");
    expect(r.stdout).toContain("[OK]");
    expect(r.stdout).not.toContain("\x1b[");
  });

  it("reads stdin and prints JSON", () => {
    const out = execFileSync(process.execPath, [CLI, "--json", "--now", "1740672100"], {
      input: FIX.x402_v1_http["X-PAYMENT"][0],
      encoding: "utf8",
    });
    const d = JSON.parse(out);
    expect(d.kind).toBe("x402.payment-payload");
    expect(d.flags.map((f: { code: string }) => f.code)).toContain("SIG_VALID");
  });

  it("reads a file path, and --strict exits 3 on danger", () => {
    const r = run(["--now", "1777343000", FIXTURE]);
    expect(r.status).toBe(0);
    expect(r.stdout.replace(/\s+/g, " ")).toContain("signed with name 'USD Coin' but Base Sepolia USDC's domain name is 'USDC'");
    expect(run(["--strict", "--now", "1777343000", FIXTURE]).status).toBe(3);
  });

  it("exits 1 on unrecognized input", () => {
    expect(run(["definitely not a payment"]).status).toBe(1);
  });

  it("rejects a malformed --now and unknown options with exit 2", () => {
    for (const args of [["--now=abc", "x"], ["--now", "1.5", "x"], ["--now"], ["--jsno", "x"]]) {
      const r = run(args);
      expect(r.status).toBe(2);
      expect(r.stderr).toMatch(/^paydecode: /);
    }
  });

  it("--help documents every option the parser accepts", () => {
    const help = run(["--help"]).stdout;
    for (const opt of ["--json", "--now", "--color", "--no-color", "--strict", "--help"]) expect(help).toContain(opt);
  });
});
