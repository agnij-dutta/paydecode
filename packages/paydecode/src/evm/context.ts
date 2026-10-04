// Shared EVM payment context (what the surrounding requirements say) plus the window, amount and
// asset checks used by both EIP-3009 and Permit2.
import { asText, duration, flag, formatDay, formatUnits, relative, short } from "../core/format.js";
import { chainName, tokensAtAddress } from "../core/networks.js";
import type { EvmToken } from "../core/networks.js";
import type { Flag, Section } from "../types.js";

export interface PaymentContext {
  scheme?: string;
  network?: string;
  asset?: string;
  payTo?: string;
  /** Required amount in atomic units. */
  amount?: string;
  /** Where `amount` came from, for messages ("accepted.amount", "maxAmountRequired"). */
  amountLabel?: string;
  extra?: Record<string, unknown>;
  maxTimeoutSeconds?: number;
}

export interface Analysis {
  sections: Section[];
  flags: Flag[];
  summary: string;
  /** Short phrase about the signature for the parent summary, e.g. "Signature valid." */
  sigPhrase: string;
  payer?: string;
}

export const hex0x = (s: unknown) => {
  const v = asText(s, "");
  return v.startsWith("0x") || v.startsWith("0X") ? v : "0x" + v;
};

export function tokenLabel(tk: EvmToken | undefined, chainId?: number): string {
  if (!tk) return "the token";
  return `${chainName(chainId ?? tk.chainId)} ${tk.symbol}`;
}

export function amountText(value: unknown, tk: EvmToken | undefined, asset?: string): string {
  if (tk) return `${formatUnits(value, tk.decimals)} ${tk.symbol}`;
  return `${asText(value)} atomic units of ${asset ? short(asset) : "an unknown token"}`;
}

export function windowFlags(after: number | undefined, before: number | undefined, now: number, ctx: PaymentContext): Flag[] {
  const flags: Flag[] = [];
  if (before !== undefined && before <= now) {
    flags.push(
      flag(
        "danger",
        "AUTH_EXPIRED",
        `Expired ${relative(before, now)} (validBefore ${formatDay(before)}). A facilitator will reject it; the payer must sign a fresh one.`,
      ),
    );
  }
  if (after !== undefined && after > now) {
    flags.push(flag("warn", "AUTH_NOT_YET_VALID", `Not valid yet: becomes usable ${relative(after, now)}. Settling before then reverts.`));
  }
  if (before !== undefined) {
    const start = after && after > 0 ? after : now;
    const span = before - start;
    const limit = Math.max(3600, (ctx.maxTimeoutSeconds ?? 0) + 600 + 60);
    if (span > 30 * 86400) {
      flags.push(
        flag(
          "danger",
          "AUTH_WINDOW_HUGE",
          `Stays spendable for ${duration(span)}. Anyone who obtains this blob can submit it until ${formatDay(before)}. x402 clients normally sign windows of a few minutes.`,
        ),
      );
    } else if (span > limit) {
      flags.push(
        flag(
          "warn",
          "AUTH_WINDOW_LONG",
          `Unusually long validity window (${duration(span)}). The reference x402 client signs for maxTimeoutSeconds plus 10 minutes; a long window widens the replay/front-run window if the blob leaks.`,
        ),
      );
    }
  }
  if (after === 0)
    flags.push(flag("info", "AUTH_NO_START", "validAfter is 0, so the authorization is usable immediately (no start time)."));
  return flags;
}

export function amountFlags(value: unknown, ctx: PaymentContext, tk: EvmToken | undefined): Flag[] {
  const flags: Flag[] = [];
  let v: bigint;
  try {
    v = BigInt(asText(value));
  } catch {
    return [flag("danger", "AMOUNT_INVALID", `Amount '${asText(value)}' is not an integer.`)];
  }
  if (v === 0n) flags.push(flag("warn", "AMOUNT_ZERO", "Authorizes a transfer of 0. Facilitators usually reject zero-value payments."));
  if (ctx.amount !== undefined) {
    let req: bigint | undefined;
    try {
      req = BigInt(asText(ctx.amount));
    } catch {
      req = undefined;
    }
    const label = ctx.amountLabel ?? "the required amount";
    if (req !== undefined) {
      const upto = ctx.scheme === "upto";
      if (v > req && !upto) {
        flags.push(
          flag(
            "danger",
            "AMOUNT_OVERPAY",
            `Signs for ${amountText(v, tk, ctx.asset)} but ${label} is ${amountText(req, tk, ctx.asset)}. The payer would overpay by ${amountText(v - req, tk, ctx.asset)}.`,
          ),
        );
      } else if (v < req) {
        flags.push(
          flag(
            "warn",
            "AMOUNT_UNDERPAY",
            `Signs for ${amountText(v, tk, ctx.asset)} but ${label} is ${amountText(req, tk, ctx.asset)}. The server should reject this as insufficient.`,
          ),
        );
      } else if (!upto || v === req) {
        flags.push(flag("ok", "AMOUNT_MATCHES", `Amount matches ${label} (${amountText(req, tk, ctx.asset)}).`));
      }
    }
  }
  return flags;
}

export function assetFlags(ctx: PaymentContext, tk: EvmToken | undefined, chainId: number | undefined): Flag[] {
  const flags: Flag[] = [];
  if (!ctx.asset) return flags;
  if (!tk) {
    const elsewhere = tokensAtAddress(ctx.asset);
    if (elsewhere.length && chainId !== undefined) {
      flags.push(
        flag(
          "danger",
          "ASSET_WRONG_CHAIN",
          `Asset ${short(ctx.asset)} is ${elsewhere.map((e) => `${chainName(e.chainId)} ${e.symbol}`).join(", ")}, but this payment is on ${chainName(chainId)}. On ${chainName(chainId)} that address is not the token you think it is.`,
        ),
      );
    } else {
      flags.push(
        flag(
          "warn",
          "UNKNOWN_ASSET",
          `Asset ${short(ctx.asset)} isn't a token paydecode knows${chainId !== undefined ? ` on ${chainName(chainId)}` : ""}. Decimals are unknown, so amounts are shown in raw atomic units. Check the contract before trusting the price.`,
        ),
      );
    }
  } else if (tk.source === "x402-default") {
    flags.push(
      flag(
        "info",
        "ASSET_FROM_X402_TABLE",
        `${tk.symbol} on ${chainName(tk.chainId)} matches x402's default asset table (domain not independently verified on-chain).`,
      ),
    );
  }
  return flags;
}

/** Decode + verify an exact/EVM EIP-3009 payload. */
