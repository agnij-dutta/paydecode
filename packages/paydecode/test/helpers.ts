import { readFileSync } from "node:fs";
import { decode } from "../src/index.js";
import type { Decoded, Unrecognized } from "../src/types.js";

export const FIX = JSON.parse(readFileSync(new URL("./fixtures/fixtures.json", import.meta.url), "utf8"));
export const readFixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

/** Inside the 65s window of the x402 fixtures (validAfter 1740672089, validBefore 1740672154). */
export const X402_NOW = 1740672100;
/** Inside the AP2 fixture mandate lifetime (iat 1777342357, exp 1777345957). */
export const AP2_NOW = 1777343000;

export const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");
export const unb64 = (s: string) => JSON.parse(Buffer.from(s, "base64").toString("utf8"));

export function codes(d: Decoded | Unrecognized): string[] {
  return d.flags.map((f) => f.code);
}

export function flagOf(d: Decoded | Unrecognized, code: string) {
  return d.flags.find((f) => f.code === code);
}

export function dec(input: string, now: number) {
  return decode(input, { now });
}

export const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
export const ANVIL_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
export const ANVIL_1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;

export const TWA_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;
