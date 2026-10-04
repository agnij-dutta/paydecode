// x402 PaymentRequirements / PaymentRequired: prices, networks and pre-signing warnings.
// Spec: https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md
import { isRecord } from "../core/encoding.js";
import { asText, duration, field, flag, formatUnits, listJoin, plural, section, short } from "../core/format.js";
import { chainName, findEvmToken, findSplToken, networkInfo, tokensAtAddress } from "../core/networks.js";
import { make } from "../core/result.js";
import { isEvmAddress } from "../crypto/eip712.js";
import type { PaymentContext } from "../evm/context.js";
import type { Decoded, Field, Flag, Section } from "../types.js";
import { EXTENSION_GLOSSARY } from "./shapes.js";

type Obj = Record<string, unknown>;

// ---------------------------------------------------------------- requirements

/** Plain-English price for an amount on a network/asset. */
export function priceText(amount: unknown, network: unknown, asset: unknown): string {
  const net = networkInfo(network);
  if (net.family === "evm") {
    const tk = findEvmToken(net.chainId, asset);
    if (tk) return `${formatUnits(amount, tk.decimals)} ${tk.symbol}`;
  } else if (net.family === "svm") {
    const tk = findSplToken(asset);
    if (tk) return `${formatUnits(amount, tk.decimals)} ${tk.symbol}`;
  }
  if (typeof asset === "string" && /^[A-Z]{3}$/.test(asset)) return `${asText(amount)} ${asset} (atomic units)`;
  return `${asText(amount)} atomic units of ${asset ? short(asset) : "an unspecified asset"}`;
}

export function transferMethod(req: Obj): string {
  const net = networkInfo(req.network);
  const extra = isRecord(req.extra) ? req.extra : {};
  if (net.family === "svm") return "SPL TransferChecked";
  if (net.family === "evm") {
    const m = typeof extra.assetTransferMethod === "string" ? extra.assetTransferMethod : "eip3009";
    return m === "eip3009" ? "EIP-3009" : m === "permit2" ? "Permit2" : m;
  }
  return "";
}

export function requirementContext(req: Obj, version: number): PaymentContext {
  return {
    scheme: typeof req.scheme === "string" ? req.scheme : undefined,
    network: typeof req.network === "string" ? req.network : undefined,
    asset: typeof req.asset === "string" ? req.asset : undefined,
    payTo: typeof req.payTo === "string" ? req.payTo : undefined,
    amount:
      version >= 2 || req.amount !== undefined
        ? ((req.amount as string | undefined) ?? (req.maxAmountRequired as string | undefined))
        : (req.maxAmountRequired as string | undefined),
    amountLabel: req.amount !== undefined ? "accepted.amount" : "maxAmountRequired",
    extra: isRecord(req.extra) ? req.extra : undefined,
    maxTimeoutSeconds: typeof req.maxTimeoutSeconds === "number" ? req.maxTimeoutSeconds : undefined,
  };
}

export interface ReqView {
  text: string;
  fields: Field[];
  flags: Flag[];
}

export function describeRequirement(req: Obj, version: number): ReqView {
  const flags: Flag[] = [];
  const net = networkInfo(req.network);
  const amount = req.amount ?? req.maxAmountRequired;
  const price = priceText(amount, req.network, req.asset);
  const extra = isRecord(req.extra) ? req.extra : {};
  const method = transferMethod(req);
  const payTo = asText(req.payTo, "");
  const scheme = asText(req.scheme, "?");
  const text = `${scheme === "upto" ? "up to " : ""}${price} on ${net.name} to ${payTo.length > 30 || isEvmAddress(payTo) ? short(payTo) : `'${payTo}'`} (${scheme}${method ? `, ${method}` : ""})`;

  if (!net.known) flags.push(flag("warn", "UNKNOWN_NETWORK", `Network '${asText(req.network)}' isn't one paydecode recognizes.`));
  if (net.family === "evm") {
    const tk = findEvmToken(net.chainId, req.asset);
    if (!tk && typeof req.asset === "string") {
      const elsewhere = tokensAtAddress(req.asset);
      flags.push(
        elsewhere.length
          ? flag(
              "danger",
              "ASSET_WRONG_CHAIN",
              `Asset ${short(req.asset)} is ${elsewhere.map((e) => `${chainName(e.chainId)} ${e.symbol}`).join(", ")}, not a token on ${net.name}.`,
            )
          : flag(
              "warn",
              "UNKNOWN_ASSET",
              `Asset ${short(req.asset)} isn't a token paydecode knows on ${net.name}; the price is shown in raw units.`,
            ),
      );
    }
    if (tk && scheme === "exact" && method === "EIP-3009") {
      if (tk.transfer === "permit2") {
        flags.push(
          flag(
            "danger",
            "ASSET_NO_EIP3009",
            `${tk.symbol} on ${net.name} doesn't implement EIP-3009, but the requirements imply the default eip3009 transfer method. Set extra.assetTransferMethod to 'permit2'.`,
          ),
        );
      }
      if (typeof extra.name === "string" && extra.name !== tk.name) {
        flags.push(
          flag(
            "danger",
            "REQUIREMENTS_DOMAIN_WRONG",
            `extra.name is '${extra.name}' but ${net.name} ${tk.symbol}'s on-chain EIP-712 domain name is '${tk.name}'. Clients that sign with this will produce signatures the token rejects.`,
          ),
        );
      }
      if (typeof extra.version === "string" && extra.version !== tk.version) {
        flags.push(
          flag(
            "danger",
            "REQUIREMENTS_DOMAIN_WRONG",
            `extra.version is '${extra.version}' but ${net.name} ${tk.symbol}'s on-chain EIP-712 domain version is '${tk.version}'.`,
          ),
        );
      }
    }
    if (scheme === "exact" && method === "EIP-3009" && (typeof extra.name !== "string" || typeof extra.version !== "string")) {
      flags.push(
        flag(
          "warn",
          "REQUIREMENTS_NO_DOMAIN",
          "extra.name / extra.version (the token's EIP-712 domain) are missing; clients have to guess them and may sign under the wrong domain.",
        ),
      );
    }
    if (payTo && !isEvmAddress(payTo))
      flags.push(
        flag("info", "PAYTO_ROLE", `payTo is '${payTo}', a role rather than an address; the actual recipient is resolved elsewhere.`),
      );
  }
  if (net.family === "svm") {
    if (typeof extra.feePayer !== "string")
      flags.push(flag("warn", "SVM_NO_FEE_PAYER", "Solana requirements should name the facilitator's fee payer in extra.feePayer."));
    if (typeof req.asset === "string" && !findSplToken(req.asset))
      flags.push(flag("warn", "UNKNOWN_ASSET", `Mint ${short(req.asset)} isn't one paydecode knows; the price is shown in raw units.`));
  }
  if (typeof req.maxTimeoutSeconds === "number" && req.maxTimeoutSeconds > 3600) {
    flags.push(
      flag(
        "warn",
        "LONG_TIMEOUT",
        `maxTimeoutSeconds is ${duration(req.maxTimeoutSeconds)}; clients will sign authorizations that stay live that long.`,
      ),
    );
  }
  try {
    if (amount !== undefined && BigInt(asText(amount)) === 0n) flags.push(flag("warn", "AMOUNT_ZERO", "Requires a payment of 0."));
  } catch {
    flags.push(flag("warn", "AMOUNT_INVALID", `Amount '${asText(amount)}' is not an integer string.`));
  }

  const fields: Field[] = [
    field("Price", price, "amount", `raw ${asText(amount)}${version === 1 ? " (maxAmountRequired)" : ""}`),
    field("Scheme", `${scheme}${method ? ` (${method})` : ""}`),
    field("Network", net.name, "text", net.caip2 ?? asText(req.network)),
    field("Pay to", payTo, payTo.length > 30 || isEvmAddress(payTo) ? "address" : "text"),
    ...(req.asset !== undefined ? [field("Asset", asText(req.asset), "address")] : []),
    ...(typeof req.maxTimeoutSeconds === "number" ? [field("Max timeout", duration(req.maxTimeoutSeconds))] : []),
    ...(typeof req.resource === "string" ? [field("Resource", req.resource)] : []),
    ...(typeof req.description === "string" && req.description ? [field("Description", req.description)] : []),
    ...(typeof req.mimeType === "string" && req.mimeType ? [field("MIME type", req.mimeType)] : []),
    ...(Object.keys(extra).length ? [field("Extra", JSON.stringify(extra), "code")] : []),
  ];
  return { text, fields, flags };
}

export function resourceText(o: Obj, first?: Obj): string | undefined {
  const r = o.resource;
  if (isRecord(r) && typeof r.url === "string") return r.url;
  if (typeof r === "string") return r;
  if (first && typeof first.resource === "string") return first.resource;
  return undefined;
}

export function resourceFields(o: Obj): Field[] {
  const r = o.resource;
  if (!isRecord(r)) return [];
  return [
    field("URL", asText(r.url, "")),
    ...(r.description ? [field("Description", asText(r.description))] : []),
    ...(r.mimeType ? [field("MIME type", asText(r.mimeType))] : []),
    ...(r.serviceName ? [field("Service", asText(r.serviceName))] : []),
  ];
}

export function extensionsSection(ext: unknown): Section[] {
  if (!isRecord(ext) || !Object.keys(ext).length) return [];
  return [
    section(
      "Extensions",
      Object.entries(ext).map(([k, v]) => field(k, JSON.stringify(v), "code", EXTENSION_GLOSSARY[k])),
    ),
  ];
}

export function decodePaymentRequired(o: Obj, now: number): Decoded {
  void now;
  const version = Number(o.x402Version);
  const accepts = (o.accepts as unknown[]).filter(isRecord) as Obj[];
  const flags: Flag[] = [];
  const sections: Section[] = [];
  const views = accepts.map((a) => describeRequirement(a, version));
  views.forEach((v, i) => {
    sections.push(section(accepts.length > 1 ? `Option ${i + 1}: ${v.text}` : "Payment required", v.fields));
    flags.push(...v.flags.map((f) => (accepts.length > 1 ? { ...f, message: `Option ${i + 1}: ${f.message}` } : f)));
  });
  const res = resourceText(o, accepts[0]);
  const desc =
    isRecord(o.resource) && typeof o.resource.description === "string"
      ? o.resource.description
      : typeof accepts[0]?.description === "string"
        ? accepts[0].description
        : undefined;
  if (isRecord(o.resource)) sections.unshift(section("Resource", resourceFields(o)));
  sections.push(...extensionsSection(o.extensions));
  if (!accepts.length) flags.push(flag("warn", "NO_ACCEPTS", "The accepts list is empty, so there is no way to pay."));
  if (version !== 1 && version !== 2) flags.push(flag("warn", "UNKNOWN_VERSION", `x402Version ${version} is not 1 or 2.`));
  const forWhat = res ? ` to access ${res}${desc ? ` (${desc})` : ""}` : "";
  const err = typeof o.error === "string" && o.error ? ` Server message: "${o.error}".` : "";
  const summary =
    accepts.length === 1
      ? `Server asks for ${views[0].text}${forWhat}.${err}`
      : `Server offers ${plural(accepts.length, "way")} to pay${forWhat}: ${listJoin(
          views.map((v) => v.text),
          "or",
        )}.${err}`;
  return make("x402.payment-required", `x402 payment required (v${version})`, summary, sections, flags, o);
}

/** Pick the analysis for a payload given its requirement context. */
