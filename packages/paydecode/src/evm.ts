// EVM payment authorizations: EIP-3009 TransferWithAuthorization and Permit2
// PermitWitnessTransferFrom, with signer recovery and domain diagnosis.
import type { Field, Flag, Section } from "./types.js";
import {
  type Domain,
  type TypeMap,
  typedDataHash,
  recoverAddress,
  isEvmAddress,
  sameAddress,
  checksumAddress,
  makeRecoverer,
  hashStructTyped,
  domainSeparator,
  concatBytes,
} from "./eip712.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import {
  networkInfo,
  chainName,
  findEvmToken,
  tokensAtAddress,
  EVM_TOKENS,
  type EvmToken,
  PERMIT2_ADDRESS,
  X402_EXACT_PERMIT2_PROXY,
  X402_UPTO_PERMIT2_PROXY,
} from "./networks.js";
import { field, flag, formatUnits, formatDay, duration, relative, short, timeField, toUnix, section } from "./format.js";
import { isRecord } from "./encoding.js";

/** What the surrounding artifact says this payment should look like. */
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

export const TRANSFER_WITH_AUTHORIZATION: TypeMap = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

const PERMIT2_EXACT_TYPES: TypeMap = {
  PermitWitnessTransferFrom: [
    { name: "permitted", type: "TokenPermissions" },
    { name: "spender", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
    { name: "witness", type: "Witness" },
  ],
  TokenPermissions: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
  ],
  Witness: [
    { name: "to", type: "address" },
    { name: "validAfter", type: "uint256" },
  ],
};

const PERMIT2_UPTO_TYPES: TypeMap = {
  ...PERMIT2_EXACT_TYPES,
  Witness: [
    { name: "to", type: "address" },
    { name: "facilitator", type: "address" },
    { name: "validAfter", type: "uint256" },
  ],
};

const hex0x = (s: unknown) => {
  const v = String(s ?? "");
  return v.startsWith("0x") || v.startsWith("0X") ? v : "0x" + v;
};

function tokenLabel(tk: EvmToken | undefined, chainId?: number): string {
  if (!tk) return "the token";
  return `${chainName(chainId ?? tk.chainId)} ${tk.symbol}`;
}

export function amountText(value: unknown, tk: EvmToken | undefined, asset?: string): string {
  if (tk) return `${formatUnits(value, tk.decimals)} ${tk.symbol}`;
  return `${String(value)} atomic units of ${asset ? short(asset) : "an unknown token"}`;
}

interface DomainHit {
  domain: Domain;
  token?: EvmToken;
  recovered: string;
}

/** Try a list of candidate domains; return the first that recovers to `from`. */
function searchDomains(
  candidates: Domain[],
  types: TypeMap,
  primary: string,
  message: Record<string, unknown>,
  signature: string,
  from: string,
): DomainHit | undefined {
  const seen = new Set<string>();
  const recover = makeRecoverer(signature);
  if (!recover) return undefined;
  const structHash = hashStructTyped(primary, types, message);
  for (const d of candidates) {
    const key = JSON.stringify([d.name, d.version, String(d.chainId), String(d.verifyingContract).toLowerCase()]);
    if (seen.has(key)) continue;
    seen.add(key);
    let digest: Uint8Array;
    try {
      digest = keccak_256(concatBytes([new Uint8Array([0x19, 0x01]), domainSeparator(d), structHash]));
    } catch {
      continue;
    }
    const rec = recover(digest);
    if (rec && sameAddress(rec, from)) {
      return { domain: d, token: findEvmToken(Number(d.chainId), d.verifyingContract), recovered: rec };
    }
  }
  return undefined;
}

function domainCandidates(chainId: number | undefined, asset: string | undefined, extra?: Record<string, unknown>): Domain[] {
  const names = new Set<string>();
  const versions = new Set<string>();
  if (typeof extra?.name === "string") names.add(extra.name);
  if (typeof extra?.version === "string") versions.add(extra.version);
  for (const n of ["USD Coin", "USDC"]) names.add(n);
  for (const v of ["2", "1"]) versions.add(v);
  const out: Domain[] = [];
  const pushToken = (cid: number, addr: string, tk?: EvmToken, narrow = false) => {
    const ns = new Set(narrow ? ["USD Coin", "USDC"] : names);
    const vs = new Set(narrow ? [] : versions);
    if (tk) {
      ns.add(tk.name);
      if (!narrow) ns.add(tk.symbol);
      vs.add(tk.version);
    }
    for (const name of ns) for (const version of vs) out.push({ name, version, chainId: cid, verifyingContract: addr });
  };
  // 1. the stated chain + asset
  if (chainId !== undefined && asset) pushToken(chainId, asset, findEvmToken(chainId, asset));
  // 2. same asset on other chains, then same chain other tokens
  if (asset) for (const tk of tokensAtAddress(asset)) pushToken(tk.chainId, tk.address, tk);
  if (chainId !== undefined) for (const tk of EVM_TOKENS.filter((x) => x.chainId === chainId)) pushToken(tk.chainId, tk.address, tk, true);
  // 3. everything we know
  for (const tk of EVM_TOKENS) pushToken(tk.chainId, tk.address, tk, true);
  return out;
}

const domainText = (d: Domain) =>
  `name '${d.name}', version '${d.version}', chainId ${String(d.chainId)}, verifyingContract ${short(d.verifyingContract)}`;

export interface SigVerdict {
  flags: Flag[];
  phrase: string;
  fields: Field[];
  /** The domain we believe the signature was made under, if any. */
  hit?: DomainHit;
}

/**
 * Verify an EIP-3009 signature and, if it fails, figure out *why*: wrong
 * domain name/version, wrong chain, wrong token, or a genuinely bad signature.
 */
export function verifyEip3009Signature(
  auth: Record<string, unknown>,
  signature: string,
  ctx: PaymentContext,
): SigVerdict {
  const flags: Flag[] = [];
  const fields: Field[] = [];
  const from = String(auth.from ?? "");
  const message = { ...auth, nonce: hex0x(auth.nonce) };
  const sig = hex0x(signature);
  const net = ctx.network ? networkInfo(ctx.network) : undefined;
  const chainId = net?.chainId;
  const asset = isEvmAddress(ctx.asset) ? ctx.asset : undefined;
  const token = findEvmToken(chainId, asset);
  const extraName = typeof ctx.extra?.name === "string" ? ctx.extra.name : undefined;
  const extraVersion = typeof ctx.extra?.version === "string" ? ctx.extra.version : undefined;

  if (!isEvmAddress(from)) {
    flags.push(flag("danger", "AUTH_FROM_INVALID", `authorization.from (${from || "missing"}) is not an EVM address.`));
    return { flags, phrase: "Signature could not be checked.", fields };
  }
  const sigBytes = sig.length - 2;
  if (!/^0x[0-9a-fA-F]+$/.test(sig) || (sigBytes !== 130 && sigBytes !== 128)) {
    flags.push(
      flag(
        "danger",
        "SIG_MALFORMED",
        `Signature is ${sigBytes / 2} bytes; an EOA EIP-3009 signature is 65 bytes. Smart-wallet (EIP-1271/6492) signatures can't be checked offline.`,
      ),
    );
    return { flags, phrase: "Signature malformed or from a smart wallet (not checked).", fields };
  }

  const claimed: Domain | undefined =
    chainId !== undefined && asset && (extraName ?? token?.name) && (extraVersion ?? token?.version)
      ? { name: extraName ?? token!.name, version: extraVersion ?? token!.version, chainId, verifyingContract: asset }
      : undefined;
  const onchain: Domain | undefined = token
    ? { name: token.name, version: token.version, chainId: token.chainId, verifyingContract: token.address }
    : undefined;
  const tryD = (d: Domain) => recoverAddress(typedDataHash(d, TRANSFER_WITH_AUTHORIZATION, "TransferWithAuthorization", message), sig);
  const claimedRec = claimed ? tryD(claimed) : null;
  const claimedOk = !!claimedRec && sameAddress(claimedRec, from);
  const domainsDiffer = !!(claimed && onchain && (claimed.name !== onchain.name || claimed.version !== onchain.version));
  const onchainOk = onchain ? (domainsDiffer ? sameAddress(tryD(onchain), from) : claimedOk) : false;
  const tl = tokenLabel(token, chainId);

  if (onchain) fields.push(field("On-chain EIP-712 domain", domainText(onchain), "code", token!.source === "onchain" ? "verified against the deployed contract" : "from x402's default asset table"));

  if (claimed && onchain && !domainsDiffer && claimedOk) {
    flags.push(flag("ok", "SIG_VALID", `Signature valid: recovers to ${short(from)} (the 'from' address) under ${tl}'s on-chain domain.`));
    fields.push(field("Recovered signer", checksumAddress(from), "address", "matches from"));
    return { flags, phrase: "Signature valid.", fields };
  }
  if (domainsDiffer && claimedOk) {
    const what = claimed!.name !== onchain!.name ? `name '${claimed!.name}'` : `version '${claimed!.version}'`;
    const real = claimed!.name !== onchain!.name ? `domain name is '${onchain!.name}'` : `domain version is '${onchain!.version}'`;
    flags.push(
      flag(
        "danger",
        "EIP712_DOMAIN_MISMATCH",
        `Signed with ${what} (copied from the requirements' extra) but ${tl}'s ${real}. The signature is internally consistent, yet the token contract computes a different digest, so transferWithAuthorization will revert with "invalid signature". Fix extra.${claimed!.name !== onchain!.name ? "name" : "version"} to '${claimed!.name !== onchain!.name ? onchain!.name : onchain!.version}' and re-sign.`,
      ),
    );
    fields.push(field("Recovered signer", checksumAddress(from), "address", "matches from, but only under the wrong domain"));
    return { flags, phrase: `Signature will be rejected on-chain: signed with ${what} but ${tl}'s ${real}.`, fields, hit: { domain: claimed!, token, recovered: from } };
  }
  if (domainsDiffer && onchainOk) {
    flags.push(flag("ok", "SIG_VALID", `Signature valid: recovers to ${short(from)} under ${tl}'s on-chain domain.`));
    flags.push(
      flag(
        "warn",
        "EXTRA_DOMAIN_WRONG",
        `The requirements advertise extra.name/version '${extraName}'/'${extraVersion}', but ${tl}'s on-chain domain is '${onchain!.name}'/'${onchain!.version}'. This client ignored extra and signed correctly; clients that trust extra will produce signatures the contract rejects.`,
      ),
    );
    return { flags, phrase: "Signature valid.", fields };
  }
  if (claimed && !onchain && claimedOk) {
    flags.push(
      flag(
        "ok",
        "SIG_VALID",
        `Signature valid for the domain in extra (${domainText(claimed)}). This token isn't in paydecode's table, so we can't confirm that domain matches the deployed contract.`,
      ),
    );
    return { flags, phrase: "Signature valid for the stated domain.", fields };
  }

  // Nothing obvious worked: search every domain we know.
  const hit = searchDomains(domainCandidates(chainId, asset, ctx.extra), TRANSFER_WITH_AUTHORIZATION, "TransferWithAuthorization", message, sig, from);
  if (hit) {
    const htk = hit.token;
    const hd = hit.domain;
    const htl = tokenLabel(htk, Number(hd.chainId));
    fields.push(field("Signed under domain", domainText(hd), "code"));
    const contextless = chainId === undefined && !asset;
    const wrongChain = chainId !== undefined && Number(hd.chainId) !== chainId;
    const wrongToken = asset && !sameAddress(hd.verifyingContract, asset);
    if (wrongChain) {
      flags.push(
        flag(
          "danger",
          "SIG_WRONG_CHAIN",
          `Signature was made for chainId ${String(hd.chainId)} (${chainName(Number(hd.chainId))}) but this payment is on ${net?.name} (chainId ${chainId}). It will not verify on ${net?.name}.`,
        ),
      );
    } else if (wrongToken) {
      flags.push(
        flag(
          "danger",
          "SIG_WRONG_TOKEN",
          `Signature names verifyingContract ${short(hd.verifyingContract)} but the payment asset is ${short(asset)}. The asset contract will reject it.`,
        ),
      );
    }
    if (htk && (hd.name !== htk.name || hd.version !== htk.version)) {
      const nameWrong = hd.name !== htk.name;
      const what = nameWrong ? `name '${hd.name}'` : `version '${hd.version}'`;
      const real = nameWrong ? `domain name is '${htk.name}'` : `domain version is '${htk.version}'`;
      const claimedBit =
        claimed && (claimed.name !== hd.name || claimed.version !== hd.version)
          ? ` (the requirements' extra says '${claimed.name}'/'${claimed.version}', and the signer used neither that nor the real domain)`
          : "";
      flags.push(
        flag(
          "danger",
          "EIP712_DOMAIN_MISMATCH",
          `Signed with ${what} but ${htl}'s ${real}${claimedBit}. ${htk.symbol}'s contract hashes the real domain, so transferWithAuthorization will revert with "invalid signature". Re-sign with ${nameWrong ? `name '${htk.name}'` : `version '${htk.version}'`}.`,
        ),
      );
      return {
        flags,
        phrase: `Signature will be rejected on-chain: signed with ${what} but ${htl}'s ${real}.`,
        fields,
        hit,
      };
    }
    if (!wrongChain && !wrongToken) {
      flags.push(
        flag(
          "ok",
          "SIG_VALID",
          contextless
            ? `Signature valid: recovers to ${short(from)} under ${htl}'s on-chain domain (inferred, the artifact doesn't name a network).`
            : `Signature valid: recovers to ${short(from)} under ${htl}'s domain.`,
        ),
      );
      if (claimed && (claimed.name !== hd.name || claimed.version !== hd.version)) {
        flags.push(flag("warn", "EXTRA_DOMAIN_WRONG", `The requirements' extra says '${claimed.name}'/'${claimed.version}', but the signature (correctly) used '${hd.name}'/'${hd.version}'.`));
      }
      return { flags, phrase: contextless ? `Signature valid (as ${htl}).` : "Signature valid.", fields, hit };
    }
    return { flags, phrase: "Signature is for a different chain or token.", fields, hit };
  }

  const ref = claimed ?? onchain;
  const rec = ref ? tryD(ref) : null;
  if (rec) fields.push(field("Recovered signer", rec, "address", `does NOT match from ${short(from)}`));
  flags.push(
    flag(
      "danger",
      "SIG_INVALID",
      ref
        ? `Signature does not match 'from'. Under ${tl}'s domain it recovers to ${short(rec)}, not ${short(from)}, and no other known USDC domain fits either. The authorization fields (to, value, validity, nonce) were changed after signing, or a different key signed it.`
        : `Signature does not recover to 'from' (${short(from)}) under any known token domain, and the artifact doesn't say which network/asset it is for, so it can't be pinned down further.`,
    ),
  );
  return { flags, phrase: "Signature INVALID.", fields };
}

/** Validity window flags shared by EIP-3009 and Permit2. */
function windowFlags(after: number | undefined, before: number | undefined, now: number, ctx: PaymentContext): Flag[] {
  const flags: Flag[] = [];
  if (before !== undefined && before <= now) {
    flags.push(flag("danger", "AUTH_EXPIRED", `Expired ${relative(before, now)} (validBefore ${formatDay(before)}). A facilitator will reject it; the payer must sign a fresh one.`));
  }
  if (after !== undefined && after > now) {
    flags.push(flag("warn", "AUTH_NOT_YET_VALID", `Not valid yet: becomes usable ${relative(after, now)}. Settling before then reverts.`));
  }
  if (before !== undefined) {
    const start = after && after > 0 ? after : now;
    const span = before - start;
    const limit = Math.max(3600, (ctx.maxTimeoutSeconds ?? 0) + 600 + 60);
    if (span > 30 * 86400) {
      flags.push(flag("danger", "AUTH_WINDOW_HUGE", `Stays spendable for ${duration(span)}. Anyone who obtains this blob can submit it until ${formatDay(before)}. x402 clients normally sign windows of a few minutes.`));
    } else if (span > limit) {
      flags.push(flag("warn", "AUTH_WINDOW_LONG", `Unusually long validity window (${duration(span)}). The reference x402 client signs for maxTimeoutSeconds plus 10 minutes; a long window widens the replay/front-run window if the blob leaks.`));
    }
  }
  if (after === 0) flags.push(flag("info", "AUTH_NO_START", "validAfter is 0, so the authorization is usable immediately (no start time)."));
  return flags;
}

function amountFlags(value: unknown, ctx: PaymentContext, tk: EvmToken | undefined): Flag[] {
  const flags: Flag[] = [];
  let v: bigint;
  try {
    v = BigInt(String(value));
  } catch {
    return [flag("danger", "AMOUNT_INVALID", `Amount '${String(value)}' is not an integer.`)];
  }
  if (v === 0n) flags.push(flag("warn", "AMOUNT_ZERO", "Authorizes a transfer of 0. Facilitators usually reject zero-value payments."));
  if (ctx.amount !== undefined) {
    let req: bigint | undefined;
    try {
      req = BigInt(String(ctx.amount));
    } catch {
      req = undefined;
    }
    const label = ctx.amountLabel ?? "the required amount";
    if (req !== undefined) {
      const upto = ctx.scheme === "upto";
      if (v > req && !upto) {
        flags.push(flag("danger", "AMOUNT_OVERPAY", `Signs for ${amountText(v, tk, ctx.asset)} but ${label} is ${amountText(req, tk, ctx.asset)}. The payer would overpay by ${amountText(v - req, tk, ctx.asset)}.`));
      } else if (v < req) {
        flags.push(flag("warn", "AMOUNT_UNDERPAY", `Signs for ${amountText(v, tk, ctx.asset)} but ${label} is ${amountText(req, tk, ctx.asset)}. The server should reject this as insufficient.`));
      } else if (!upto || v === req) {
        flags.push(flag("ok", "AMOUNT_MATCHES", `Amount matches ${label} (${amountText(req, tk, ctx.asset)}).`));
      }
    }
  }
  return flags;
}

function assetFlags(ctx: PaymentContext, tk: EvmToken | undefined, chainId: number | undefined): Flag[] {
  const flags: Flag[] = [];
  if (!ctx.asset) return flags;
  if (!tk) {
    const elsewhere = tokensAtAddress(ctx.asset);
    if (elsewhere.length && chainId !== undefined) {
      flags.push(flag("danger", "ASSET_WRONG_CHAIN", `Asset ${short(ctx.asset)} is ${elsewhere.map((e) => `${chainName(e.chainId)} ${e.symbol}`).join(", ")}, but this payment is on ${chainName(chainId)}. On ${chainName(chainId)} that address is not the token you think it is.`));
    } else {
      flags.push(flag("warn", "UNKNOWN_ASSET", `Asset ${short(ctx.asset)} isn't a token paydecode knows${chainId !== undefined ? ` on ${chainName(chainId)}` : ""}. Decimals are unknown, so amounts are shown in raw atomic units. Check the contract before trusting the price.`));
    }
  } else if (tk.source === "x402-default") {
    flags.push(flag("info", "ASSET_FROM_X402_TABLE", `${tk.symbol} on ${chainName(tk.chainId)} matches x402's default asset table (domain not independently verified on-chain).`));
  }
  return flags;
}

/** Decode + verify an exact/EVM EIP-3009 payload. */
export function analyzeEip3009(payload: Record<string, unknown>, ctx: PaymentContext, now: number): Analysis {
  const auth = (isRecord(payload.authorization) ? payload.authorization : {}) as Record<string, unknown>;
  const signature = String(payload.signature ?? "");
  const net = ctx.network ? networkInfo(ctx.network) : undefined;
  const chainId = net?.chainId;
  const tk = findEvmToken(chainId, ctx.asset);
  const flags: Flag[] = [];

  const after = toUnix(auth.validAfter);
  const before = toUnix(auth.validBefore);
  const from = String(auth.from ?? "");
  const to = String(auth.to ?? "");

  const sig = verifyEip3009Signature(auth, signature, ctx);
  // If we inferred the token from the signature (no network in the artifact), use it for display.
  const inferred =
    !tk && !ctx.asset && sig.hit?.token && (chainId === undefined || sig.hit.token.chainId === chainId) ? sig.hit.token : undefined;
  const shownTk = tk ?? inferred;
  const shownNet = net?.name ?? (shownTk ? `${chainName(shownTk.chainId)} (inferred from signature)` : undefined);
  if (inferred) {
    flags.push(
      flag(
        "info",
        "ASSET_INFERRED",
        `The artifact doesn't name the token; the signature's EIP-712 domain identifies it as ${chainName(inferred.chainId)} ${inferred.symbol} (${short(inferred.address)}).`,
      ),
    );
  }
  const amt = amountText(auth.value, shownTk, ctx.asset);

  flags.push(...sig.flags);
  flags.push(...windowFlags(after, before, now, ctx));
  flags.push(...amountFlags(auth.value, ctx, shownTk));
  flags.push(...assetFlags(ctx, tk, chainId));
  if (ctx.payTo && isEvmAddress(ctx.payTo) && isEvmAddress(to)) {
    if (!sameAddress(ctx.payTo, to)) {
      flags.push(flag("danger", "PAYTO_MISMATCH", `Pays ${short(to)} but the requirements say payTo is ${short(ctx.payTo)}. Money would go to the wrong address; the server should refuse it.`));
    } else flags.push(flag("ok", "PAYTO_MATCHES", `Recipient matches the requirements' payTo (${short(to)}).`));
  }
  if (isEvmAddress(from) && sameAddress(from, to)) flags.push(flag("warn", "SELF_PAYMENT", "from and to are the same address: this pays itself."));
  if (typeof auth.nonce === "string" && !/^(0x)?[0-9a-fA-F]{64}$/.test(auth.nonce)) {
    flags.push(flag("warn", "NONCE_FORMAT", `Nonce '${short(auth.nonce, 10, 4)}' is not 32 bytes of hex; EIP-3009 nonces are bytes32.`));
  }

  const fields: Field[] = [
    field("Payer (from)", from, "address"),
    field("Recipient (to)", to, "address"),
    field("Amount", amt, "amount", `raw value ${String(auth.value)}`),
    field("Network", shownNet ?? "not stated", "text", net?.caip2),
    ...(ctx.asset ? [field("Asset", ctx.asset, "address", tk ? `${tk.symbol}, ${tk.decimals} decimals` : "unknown token")] : []),
    timeField("Valid after", after, now, auth.validAfter),
    timeField("Valid before", before, now, auth.validBefore),
    ...(after !== undefined && before !== undefined
      ? [field("Window", duration(before - (after > 0 ? after : now)), "text", after > 0 ? undefined : "measured from now, since validAfter is 0")]
      : []),
    field("Nonce", String(auth.nonce ?? ""), "hash"),
  ];

  let when: string;
  if (after !== undefined && before !== undefined && after > 0) when = `valid for ${duration(before - after)} starting ${formatDay(after)}`;
  else if (before !== undefined) when = `valid until ${formatDay(before)}`;
  else when = "with no stated validity window";
  const state = before !== undefined && before <= now ? ` (expired ${relative(before, now)})` : after !== undefined && after > now ? ` (not valid until ${relative(after, now)})` : "";
  const summary = `Authorizes ${short(from)} to pay ${amt}${shownNet ? ` on ${shownNet.replace(" (inferred from signature)", "")}` : ""} to ${short(to)}, ${when}${state}. ${sig.phrase}`;

  return {
    sections: [section("EIP-3009 transfer authorization", fields), section("Signature", [field("Signature", signature, "code"), ...sig.fields])],
    flags,
    summary,
    sigPhrase: sig.phrase,
    payer: from,
  };
}

/** Decode + verify an exact/upto EVM Permit2 payload. */
export function analyzePermit2(payload: Record<string, unknown>, ctx: PaymentContext, now: number): Analysis {
  const p = (isRecord(payload.permit2Authorization) ? payload.permit2Authorization : {}) as Record<string, unknown>;
  const permitted = (isRecord(p.permitted) ? p.permitted : {}) as Record<string, unknown>;
  const witness = (isRecord(p.witness) ? p.witness : {}) as Record<string, unknown>;
  const signature = hex0x(payload.signature);
  const net = ctx.network ? networkInfo(ctx.network) : undefined;
  const chainId = net?.chainId;
  const token = String(permitted.token ?? ctx.asset ?? "");
  const tk = findEvmToken(chainId, token);
  const from = String(p.from ?? "");
  const to = String(witness.to ?? "");
  const deadline = toUnix(p.deadline);
  const validAfter = toUnix(witness.validAfter);
  const isUpto = "facilitator" in witness || ctx.scheme === "upto";
  const expectedSpender = isUpto ? X402_UPTO_PERMIT2_PROXY : X402_EXACT_PERMIT2_PROXY;
  const amt = amountText(permitted.amount, tk, token);
  const flags: Flag[] = [];
  const types = isUpto ? PERMIT2_UPTO_TYPES : PERMIT2_EXACT_TYPES;
  const message = { permitted, spender: p.spender, nonce: p.nonce, deadline: p.deadline, witness };

  // Spender check: the whole security model of x402 Permit2 rests on it.
  if (!isEvmAddress(p.spender)) {
    flags.push(flag("danger", "PERMIT2_SPENDER_MISSING", "No valid spender in the Permit2 authorization."));
  } else if (!sameAddress(p.spender, expectedSpender)) {
    const other = sameAddress(p.spender, isUpto ? X402_EXACT_PERMIT2_PROXY : X402_UPTO_PERMIT2_PROXY);
    flags.push(
      flag(
        "danger",
        "PERMIT2_SPENDER_NOT_PROXY",
        other
          ? `Spender is the x402 ${isUpto ? "exact" : "upto"} proxy, but this is ${isUpto ? "an upto" : "an exact"} payment. Settlement will fail.`
          : `Spender is ${short(p.spender)}, not the x402 Permit2 proxy (${short(expectedSpender)}). Permit2 lets the spender move these tokens anywhere, so this signature hands ${amt} to an arbitrary contract instead of enforcing the witness recipient.`,
      ),
    );
  } else flags.push(flag("ok", "PERMIT2_SPENDER_OK", `Spender is the canonical x402 ${isUpto ? "upto" : "exact"} Permit2 proxy, which enforces the witness recipient.`));

  // Signature
  let sigPhrase = "Signature INVALID.";
  const sigFields: Field[] = [field("Signature", signature, "code")];
  if (chainId === undefined) {
    flags.push(flag("info", "SIG_NOT_CHECKED", "Network not stated, so the Permit2 signature (which commits to chainId) wasn't checked."));
    sigPhrase = "Signature not checked (no network).";
  } else {
    const dom = (cid: number): Domain => ({ name: "Permit2", chainId: cid, verifyingContract: PERMIT2_ADDRESS });
    let rec: string | null = null;
    try {
      rec = recoverAddress(typedDataHash(dom(chainId), types, "PermitWitnessTransferFrom", message), signature);
    } catch {
      rec = null;
    }
    if (rec && sameAddress(rec, from)) {
      flags.push(flag("ok", "SIG_VALID", `Signature valid: recovers to ${short(from)} under the Permit2 domain on ${net!.name}.`));
      sigPhrase = "Signature valid.";
      sigFields.push(field("Recovered signer", checksumAddress(from), "address", "matches from"));
    } else {
      const chains = [...new Set(EVM_TOKENS.map((x) => x.chainId))].filter((c) => c !== chainId);
      let other: number | undefined;
      for (const c of chains) {
        try {
          const r = recoverAddress(typedDataHash(dom(c), types, "PermitWitnessTransferFrom", message), signature);
          if (r && sameAddress(r, from)) {
            other = c;
            break;
          }
        } catch {
          /* skip */
        }
      }
      if (other !== undefined) {
        flags.push(flag("danger", "SIG_WRONG_CHAIN", `Permit2 signature was made for ${chainName(other)} (chainId ${other}), not ${net!.name}. It will not verify here.`));
        sigPhrase = `Signature is for ${chainName(other)}, not ${net!.name}.`;
      } else {
        flags.push(
          flag(
            "danger",
            "SIG_INVALID",
            `Signature does not match 'from'. It recovers to ${rec ? short(rec) : "nothing"}, not ${short(from)}. The permit fields were changed after signing, or a different key signed it.`,
          ),
        );
      }
      if (rec) sigFields.push(field("Recovered signer", rec, "address", `does NOT match from ${short(from)}`));
    }
  }

  // Window + amounts + recipient
  flags.push(...windowFlags(validAfter, deadline, now, ctx));
  flags.push(...amountFlags(permitted.amount, ctx, tk));
  flags.push(...assetFlags({ ...ctx, asset: token }, tk, chainId));
  if (ctx.asset && token && !sameAddress(ctx.asset, token)) {
    flags.push(flag("danger", "PERMIT2_TOKEN_MISMATCH", `Permits token ${short(token)} but the requirements ask for ${short(ctx.asset)}.`));
  }
  if (ctx.payTo && isEvmAddress(ctx.payTo) && isEvmAddress(to)) {
    if (!sameAddress(ctx.payTo, to)) flags.push(flag("danger", "PAYTO_MISMATCH", `Witness recipient is ${short(to)} but the requirements say payTo is ${short(ctx.payTo)}.`));
    else flags.push(flag("ok", "PAYTO_MATCHES", `Witness recipient matches payTo (${short(to)}).`));
  }
  flags.push(flag("info", "PERMIT2_APPROVAL_NEEDED", `Permit2 only works if ${short(from)} has approved the Permit2 contract for this token (or the payload carries an eip2612GasSponsoring / erc20ApprovalGasSponsoring extension).`));

  const fields: Field[] = [
    field("Payer (from)", from, "address"),
    field("Recipient (witness.to)", to, "address"),
    ...(isUpto ? [field("Facilitator (witness.facilitator)", String(witness.facilitator ?? ""), "address")] : []),
    field(isUpto ? "Maximum amount" : "Amount", amt, "amount", `raw ${String(permitted.amount)}`),
    field("Token", token, "address", tk ? `${tk.symbol}, ${tk.decimals} decimals` : "unknown token"),
    field("Spender", String(p.spender ?? ""), "address", sameAddress(p.spender, expectedSpender) ? "x402 Permit2 proxy" : "NOT the x402 proxy"),
    field("Network", net?.name ?? "not stated", "text", net?.caip2),
    timeField("Valid after (witness)", validAfter, now, witness.validAfter),
    timeField("Deadline", deadline, now, p.deadline),
    field("Permit2 nonce", String(p.nonce ?? ""), "code"),
  ];
  const state = deadline !== undefined && deadline <= now ? ` (expired ${relative(deadline, now)})` : "";
  const summary = `Permit2 authorization for ${short(from)} to pay ${isUpto ? "up to " : ""}${amt}${net ? ` on ${net.name}` : ""} to ${short(to)} through ${sameAddress(p.spender, expectedSpender) ? "the x402 proxy" : `spender ${short(p.spender)}`}, valid until ${deadline !== undefined ? formatDay(deadline) : "an unstated deadline"}${state}. ${sigPhrase}`;
  return {
    sections: [section(`Permit2 PermitWitnessTransferFrom${isUpto ? " (upto)" : ""}`, fields), section("Signature", sigFields)],
    flags,
    summary,
    sigPhrase,
    payer: from,
  };
}
