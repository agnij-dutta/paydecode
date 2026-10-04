// x402 v1 + v2: PaymentRequired, PaymentPayload, SettleResponse, VerifyResponse,
// facilitator /verify and /settle bodies, and /supported.
import type { Decoded, Field, Flag, Section } from "./types.js";
import { isRecord, decodeBase64 } from "./encoding.js";
import { field, flag, formatUnits, short, section, sortFlags, duration, listJoin, plural } from "./format.js";
import { networkInfo, findEvmToken, findSplToken, chainName, tokensAtAddress } from "./networks.js";
import { isEvmAddress } from "./eip712.js";
import { analyzeEip3009, analyzePermit2, type Analysis, type PaymentContext } from "./evm.js";
import { analyzeSvmTransaction } from "./svm.js";
import { asText } from "./format.js";

type Obj = Record<string, unknown>;

export function make(
  kind: string,
  title: string,
  summary: string,
  sections: Section[],
  flags: Flag[],
  raw: unknown,
  children?: Decoded[],
): Decoded {
  const d: Decoded = { kind, title, summary, sections: sections.filter((s) => s.fields.length), flags: sortFlags(flags), raw };
  if (children && children.length) d.children = children;
  return d;
}

// ---------------------------------------------------------------- shape tests

export const isPaymentRequired = (o: Obj) => typeof o.x402Version === "number" && Array.isArray(o.accepts);
export const isPaymentPayload = (o: Obj) =>
  typeof o.x402Version === "number" &&
  isRecord(o.payload) &&
  (isRecord(o.accepted) || typeof o.scheme === "string" || typeof o.network === "string");
export const isSettleResponse = (o: Obj) => typeof o.success === "boolean" && ("transaction" in o || "network" in o || "errorReason" in o);
export const isVerifyResponse = (o: Obj) => typeof o.isValid === "boolean";
export const isFacilitatorRequest = (o: Obj) => isRecord(o.paymentPayload) && (isRecord(o.paymentRequirements) || "x402Version" in o);
export const isSupported = (o: Obj) => Array.isArray(o.kinds) && o.kinds.every((k) => isRecord(k) && "scheme" in k);
/** A bare PaymentRequirements object (one entry of `accepts`). */
export const isRequirement = (o: Obj) =>
  typeof o.scheme === "string" && typeof o.network === "string" && "payTo" in o && ("amount" in o || "maxAmountRequired" in o);

// ---------------------------------------------------------------- glossary

const ERROR_GLOSSARY: Record<string, string> = {
  insufficient_funds: "the payer's wallet doesn't hold enough of the asset",
  invalid_exact_evm_payload_signature: "the EIP-712 signature didn't verify (often a wrong domain name/version or chain)",
  invalid_exact_evm_payload_authorization_valid_after: "the authorization isn't valid yet (validAfter is in the future)",
  invalid_exact_evm_payload_authorization_valid_before: "the authorization expired (validBefore has passed)",
  invalid_exact_evm_payload_authorization_value_mismatch: "the signed amount doesn't match the required amount",
  invalid_exact_evm_payload_recipient_mismatch: "the signed recipient doesn't match payTo",
  invalid_network: "the network isn't supported or doesn't match",
  invalid_payload: "the payment payload is malformed",
  invalid_payment_requirements: "the payment requirements are malformed",
  invalid_scheme: "the scheme isn't supported",
  invalid_transaction_state: "the on-chain transaction ended in an unexpected state",
  invalid_x402_version: "the x402 protocol version isn't supported",
  permit2_allowance_required: "the payer hasn't approved the Permit2 contract for this token",
  settle_failed: "the facilitator couldn't land the transaction",
  unexpected_settle_error: "the facilitator hit an internal error while settling",
  unexpected_verify_error: "the facilitator hit an internal error while verifying",
  unsupported_asset_transfer_method: "the facilitator doesn't support this assetTransferMethod",
  unsupported_payment_flow: "the facilitator doesn't support this paymentFlow",
  unsupported_scheme: "the facilitator doesn't support this scheme",
  duplicate_settlement: "this payment was already settled (replay)",
};

export const explainError = (code: unknown) => {
  const c = asText(code, "");
  return ERROR_GLOSSARY[c] ? `${c} (${ERROR_GLOSSARY[c]})` : c;
};

const EXTENSION_GLOSSARY: Record<string, string> = {
  bazaar: "discovery metadata for the x402 Bazaar",
  "sign-in-with-x": "Sign-In-With-X: proves wallet ownership to log in",
  payment_identifier: "idempotency key for the payment",
  "offer-and-receipt": "signed offer and receipt objects",
  builder_code: "attribution code for the integrator",
  "extension-auth-hints": "hints about which auth the server accepts",
  eip2612GasSponsoring: "EIP-2612 permit so the facilitator can approve Permit2 gaslessly",
  erc20ApprovalGasSponsoring: "pre-signed ERC-20 approval the facilitator submits for Permit2",
};

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

function transferMethod(req: Obj): string {
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

interface ReqView {
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

function resourceText(o: Obj, first?: Obj): string | undefined {
  const r = o.resource;
  if (isRecord(r) && typeof r.url === "string") return r.url;
  if (typeof r === "string") return r;
  if (first && typeof first.resource === "string") return first.resource;
  return undefined;
}

function resourceFields(o: Obj): Field[] {
  const r = o.resource;
  if (!isRecord(r)) return [];
  return [
    field("URL", asText(r.url, "")),
    ...(r.description ? [field("Description", asText(r.description))] : []),
    ...(r.mimeType ? [field("MIME type", asText(r.mimeType))] : []),
    ...(r.serviceName ? [field("Service", asText(r.serviceName))] : []),
  ];
}

function extensionsSection(ext: unknown): Section[] {
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
export function analyzePayload(payload: Obj, ctx: PaymentContext, now: number): Analysis | undefined {
  const fam = networkInfo(ctx.network).family;
  if (isRecord(payload.authorization)) return analyzeEip3009(payload, ctx, now);
  if (isRecord(payload.permit2Authorization)) return analyzePermit2(payload, ctx, now);
  if (typeof payload.transaction === "string" && (fam === "svm" || fam === "other")) {
    const bytes = decodeBase64(payload.transaction);
    if (bytes) {
      try {
        return analyzeSvmTransaction(payload.transaction, bytes, ctx, now);
      } catch (e) {
        return {
          sections: [section("Transaction", [field("Transaction (base64)", payload.transaction, "code")])],
          flags: [
            flag("danger", "SVM_TX_UNPARSEABLE", `The transaction bytes don't parse as a Solana transaction: ${(e as Error).message}.`),
          ],
          summary: "Solana payment whose transaction can't be parsed.",
          sigPhrase: "Signature not checked.",
        };
      }
    }
  }
  return undefined;
}

export function decodePaymentPayload(o: Obj, now: number, requirements?: Obj): Decoded {
  const version = Number(o.x402Version);
  const accepted = isRecord(o.accepted) ? o.accepted : undefined;
  const reqSrc = accepted ?? requirements;
  const base: PaymentContext = reqSrc
    ? requirementContext(reqSrc, version)
    : { scheme: typeof o.scheme === "string" ? o.scheme : undefined, network: typeof o.network === "string" ? o.network : undefined };
  if (accepted === undefined && requirements)
    base.amountLabel = "paymentRequirements." + (requirements.amount !== undefined ? "amount" : "maxAmountRequired");
  // v1 payload carries scheme/network at top level; prefer them if no requirement
  if (!base.network && typeof o.network === "string") base.network = o.network;
  if (!base.scheme && typeof o.scheme === "string") base.scheme = o.scheme;
  const payload = o.payload as Obj;
  const flags: Flag[] = [];
  const sections: Section[] = [];
  const analysis = analyzePayload(payload, base, now);
  const res = resourceText(o, requirements);
  if (requirements && accepted) {
    // facilitator body with both: they must agree
    for (const k of ["network", "asset", "payTo", "amount", "scheme"]) {
      if (
        requirements[k] !== undefined &&
        accepted[k] !== undefined &&
        asText(requirements[k]).toLowerCase() !== asText(accepted[k]).toLowerCase()
      ) {
        flags.push(
          flag(
            "danger",
            "ACCEPTED_MISMATCH",
            `paymentPayload.accepted.${k} (${short(accepted[k], 10, 6)}) differs from paymentRequirements.${k} (${short(requirements[k], 10, 6)}).`,
          ),
        );
      }
    }
  }
  if (version === 1 && requirements && typeof o.network === "string" && requirements.network !== o.network) {
    flags.push(
      flag(
        "danger",
        "NETWORK_MISMATCH",
        `Payload network '${o.network}' differs from the requirements' '${asText(requirements.network)}'.`,
      ),
    );
  }
  if (!reqSrc && version === 1 && analysis && isRecord(payload.authorization)) {
    flags.push(
      flag(
        "info",
        "NO_REQUIREMENTS",
        "v1 payloads don't carry the requirements, so payTo, amount and asset can't be cross-checked. Paste the facilitator /verify body to check them.",
      ),
    );
  }
  let summary: string;
  if (analysis) {
    flags.push(...analysis.flags);
    sections.push(...analysis.sections);
    summary = analysis.summary;
  } else {
    summary = `x402 ${asText(base.scheme, "")} payment on ${networkInfo(base.network).name} with a payload paydecode doesn't know how to check.`;
    flags.push(
      flag(
        "warn",
        "PAYLOAD_UNKNOWN",
        `Payload fields (${Object.keys(payload).join(", ")}) don't match the EIP-3009, Permit2 or Solana exact formats.`,
      ),
    );
    sections.push(
      section(
        "Payload",
        Object.entries(payload).map(([k, v]) => field(k, typeof v === "string" ? v : JSON.stringify(v), "code")),
      ),
    );
  }
  if (accepted) sections.push(section("Accepted requirements", describeRequirement(accepted, version).fields));
  if (isRecord(o.resource)) sections.unshift(section("Resource", resourceFields(o)));
  else if (res) sections.unshift(section("Resource", [field("URL", res)]));
  sections.push(...extensionsSection(o.extensions));
  const scheme = asText(base.scheme, "");
  return make("x402.payment-payload", `x402 payment (v${version}${scheme ? `, ${scheme}` : ""})`, summary, sections, flags, o);
}

const PLACEHOLDER_TX = /^0x(1234567890abcdef){4}$/i;

export function decodeSettleResponse(o: Obj): Decoded {
  const net = o.network !== undefined ? networkInfo(o.network) : undefined;
  const flags: Flag[] = [];
  const tx = asText(o.transaction, "");
  const payer = typeof o.payer === "string" ? o.payer : undefined;
  let summary: string;
  if (o.success) {
    summary = `Settlement succeeded${net ? ` on ${net.name}` : ""}${tx ? `: transaction ${short(tx, 10, 6)}` : ""}${payer ? `, paid by ${short(payer)}` : ""}${o.amount !== undefined ? ` (charged ${asText(o.amount)} atomic units)` : ""}.`;
    flags.push(flag("ok", "SETTLED", "The facilitator reports the payment landed on-chain."));
    if (!tx)
      flags.push(
        flag("warn", "NO_TX_HASH", "Marked successful but no transaction hash was returned, so there's nothing to look up on-chain."),
      );
  } else {
    summary = `Settlement failed${net ? ` on ${net.name}` : ""}: ${explainError(o.errorReason ?? "no reason given")}.${typeof o.errorMessage === "string" ? ` "${o.errorMessage}"` : ""}${payer ? ` Payer ${short(payer)}.` : ""}`;
    flags.push(flag("danger", "SETTLE_FAILED", `Settlement failed: ${explainError(o.errorReason ?? "unknown")}. No money moved.`));
  }
  if (PLACEHOLDER_TX.test(tx))
    flags.push(
      flag(
        "info",
        "PLACEHOLDER_TX",
        "The transaction hash looks like a documentation placeholder (0x1234567890abcdef...), not a real transaction.",
      ),
    );
  const fields: Field[] = [
    field("Success", asText(o.success)),
    ...(o.errorReason ? [field("Error reason", explainError(o.errorReason))] : []),
    ...(o.errorMessage ? [field("Error message", asText(o.errorMessage))] : []),
    ...(tx ? [field("Transaction", tx, "hash")] : []),
    ...(net ? [field("Network", net.name, "text", net.caip2 ?? asText(o.network))] : []),
    ...(payer ? [field("Payer", payer, "address")] : []),
    ...(o.amount !== undefined ? [field("Amount charged", asText(o.amount), "amount")] : []),
  ];
  return make(
    "x402.settle-response",
    "x402 settlement response",
    summary,
    [section("Settlement", fields), ...extensionsSection(o.extensions)],
    flags,
    o,
  );
}

export function decodeVerifyResponse(o: Obj): Decoded {
  const payer = typeof o.payer === "string" ? o.payer : undefined;
  const ok = o.isValid === true;
  const summary = ok
    ? `Facilitator says the payment is valid${payer ? ` (payer ${short(payer)})` : ""} and can be settled.`
    : `Facilitator rejected the payment: ${explainError(o.invalidReason ?? "no reason given")}.${typeof o.invalidMessage === "string" ? ` "${o.invalidMessage}"` : ""}`;
  return make(
    "x402.verify-response",
    "x402 verify response",
    summary,
    [
      section("Verification", [
        field("Valid", asText(o.isValid)),
        ...(o.invalidReason ? [field("Reason", explainError(o.invalidReason))] : []),
        ...(o.invalidMessage ? [field("Message", asText(o.invalidMessage))] : []),
        ...(payer ? [field("Payer", payer, "address")] : []),
      ]),
    ],
    [
      ok
        ? flag("ok", "VERIFIED", "Facilitator verification passed.")
        : flag("danger", "VERIFY_FAILED", `Verification failed: ${explainError(o.invalidReason ?? "unknown")}.`),
    ],
    o,
  );
}

export function decodeFacilitatorRequest(o: Obj, now: number, endpoint?: string): Decoded {
  const pp = o.paymentPayload as Obj;
  const req = isRecord(o.paymentRequirements) ? o.paymentRequirements : undefined;
  const child = decodePaymentPayload(pp, now, req);
  const reqView = req ? describeRequirement(req, Number(pp.x402Version ?? o.x402Version ?? 2)) : undefined;
  const summary = `Facilitator ${endpoint ? `/${endpoint} ` : ""}request: ${child.summary}`;
  return make(
    "x402.facilitator-request",
    `x402 facilitator ${endpoint ? `/${endpoint}` : "/verify or /settle"} request`,
    summary,
    [...(reqView ? [section("Payment requirements", reqView.fields)] : []), ...child.sections],
    [...child.flags, ...(reqView?.flags ?? [])],
    o,
    [],
  );
}

export function decodeSupported(o: Obj): Decoded {
  const kinds = (o.kinds as Obj[]).filter(isRecord);
  const byScheme = new Map<string, Set<string>>();
  for (const k of kinds) {
    const s = `${asText(k.scheme)} (v${asText(k.x402Version, "?")})`;
    if (!byScheme.has(s)) byScheme.set(s, new Set());
    byScheme.get(s)!.add(networkInfo(k.network).name);
  }
  const parts = [...byScheme.entries()].map(([s, nets]) => `${s} on ${listJoin([...nets])}`);
  const signers = isRecord(o.signers) ? o.signers : {};
  const fields = kinds.map((k) =>
    field(
      `${asText(k.scheme)} v${asText(k.x402Version, "?")}`,
      networkInfo(k.network).name,
      "text",
      `${asText(k.network)}${isRecord(k.extra) ? ` extra ${JSON.stringify(k.extra)}` : ""}`,
    ),
  );
  return make(
    "x402.supported",
    "x402 facilitator /supported",
    `Facilitator supports ${plural(kinds.length, "scheme/network pair")}: ${parts.join("; ")}.`,
    [
      section("Supported kinds", fields),
      ...(Object.keys(signers).length
        ? [
            section(
              "Signers",
              Object.entries(signers).map(([k, v]) => field(k, Array.isArray(v) ? v.join(", ") : JSON.stringify(v), "address")),
            ),
          ]
        : []),
      ...(Array.isArray(o.extensions) && o.extensions.length
        ? [section("Extensions", [field("Extensions", (o.extensions as unknown[]).map(String).join(", "))])]
        : []),
    ],
    [],
    o,
  );
}

export function decodeRequirement(o: Obj): Decoded {
  const v = describeRequirement(o, o.amount !== undefined ? 2 : 1);
  return make(
    "x402.payment-requirements",
    "x402 payment requirements",
    `Requirement to pay ${v.text}.`,
    [section("Requirement", v.fields)],
    v.flags,
    o,
  );
}
