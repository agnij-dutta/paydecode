// EIP-3009 signature verification with EIP-712 domain diagnosis. When the signature does not
// recover to `from`, candidate domains are searched to explain why (wrong name/version/chain/token).
// Specs: https://eips.ethereum.org/EIPS/eip-3009 and https://eips.ethereum.org/EIPS/eip-712
import { keccak_256 } from "@noble/hashes/sha3.js";
import { asText, field, flag, short } from "../core/format.js";
import { EVM_TOKENS, chainName, findEvmToken, networkInfo, tokensAtAddress } from "../core/networks.js";
import type { EvmToken } from "../core/networks.js";
import {
  checksumAddress,
  concatBytes,
  domainSeparator,
  hashStructTyped,
  isEvmAddress,
  makeRecoverer,
  recoverAddress,
  sameAddress,
  typedDataHash,
} from "../crypto/eip712.js";
import type { Domain, TypeMap } from "../crypto/eip712.js";
import { hex0x, tokenLabel } from "./context.js";
import type { PaymentContext } from "./context.js";
import type { Field, Flag } from "../types.js";

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

export interface DomainHit {
  domain: Domain;
  token?: EvmToken;
  recovered: string;
}

/** Try a list of candidate domains; return the first that recovers to `from`. */
export function searchDomains(
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
    const key = JSON.stringify([d.name, d.version, asText(d.chainId), asText(d.verifyingContract).toLowerCase()]);
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

export function domainCandidates(chainId: number | undefined, asset: string | undefined, extra?: Record<string, unknown>): Domain[] {
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

export const domainText = (d: Domain) =>
  `name '${d.name}', version '${d.version}', chainId ${asText(d.chainId)}, verifyingContract ${short(d.verifyingContract)}`;

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
export function verifyEip3009Signature(auth: Record<string, unknown>, signature: string, ctx: PaymentContext): SigVerdict {
  const flags: Flag[] = [];
  const fields: Field[] = [];
  const from = asText(auth.from, "");
  const message = { ...auth, nonce: hex0x(auth.nonce) };
  const sig = hex0x(signature);
  const net = ctx.network ? networkInfo(ctx.network) : undefined;
  const chainId = net?.chainId;
  const asset = isEvmAddress(ctx.asset) ? ctx.asset : undefined;
  const token = findEvmToken(chainId, asset);
  const extraName = typeof ctx.extra?.name === "string" ? ctx.extra.name : undefined;
  const extraVersion = typeof ctx.extra?.version === "string" ? ctx.extra.version : undefined;

  if (!isEvmAddress(from)) {
    flags.push(flag("danger", "AUTH_FROM_INVALID", `authorization.from (${asText(auth.from, "missing")}) is not an EVM address.`));
    return { flags, phrase: "Signature could not be checked.", fields };
  }
  const bad: string[] = [];
  if (!isEvmAddress(auth.to)) bad.push(`to (${asText(auth.to, "missing")}) is not an address`);
  for (const k of ["value", "validAfter", "validBefore"]) {
    if (!/^\d+$/.test(asText(auth[k], ""))) bad.push(`${k} (${asText(auth[k], "missing")}) is not a non-negative integer`);
  }
  if (!/^(0x)?[0-9a-fA-F]{1,64}$/.test(asText(auth.nonce, "")))
    bad.push(`nonce (${short(asText(auth.nonce, "missing"), 10, 4)}) is not bytes32 hex`);
  if (bad.length) {
    flags.push(
      flag(
        "danger",
        "AUTH_FIELD_INVALID",
        `The authorization is malformed: ${bad.join("; ")}. No token contract will accept it, and the signature can't be checked.`,
      ),
    );
    return { flags, phrase: "Signature not checked (malformed authorization).", fields };
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
  const tryD = (d: Domain) => {
    try {
      return recoverAddress(typedDataHash(d, TRANSFER_WITH_AUTHORIZATION, "TransferWithAuthorization", message), sig);
    } catch {
      return null;
    }
  };
  const claimedRec = claimed ? tryD(claimed) : null;
  const claimedOk = !!claimedRec && sameAddress(claimedRec, from);
  const domainsDiffer = !!(claimed && onchain && (claimed.name !== onchain.name || claimed.version !== onchain.version));
  const onchainOk = onchain ? (domainsDiffer ? sameAddress(tryD(onchain), from) : claimedOk) : false;
  const tl = tokenLabel(token, chainId);

  if (onchain)
    fields.push(
      field(
        "On-chain EIP-712 domain",
        domainText(onchain),
        "code",
        token!.source === "onchain" ? "verified against the deployed contract" : "from x402's default asset table",
      ),
    );

  if (claimed && onchain && !domainsDiffer && claimedOk) {
    flags.push(flag("ok", "SIG_VALID", `Signature valid: recovers to ${short(from)} (the 'from' address) under ${tl}'s on-chain domain.`));
    fields.push(field("Recovered signer", checksumAddress(from), "address", "matches from"));
    return { flags, phrase: "Signature valid.", fields };
  }
  if (domainsDiffer && claimedOk) {
    const what = claimed.name !== onchain.name ? `name '${claimed.name}'` : `version '${claimed.version}'`;
    const real = claimed.name !== onchain.name ? `domain name is '${onchain.name}'` : `domain version is '${onchain.version}'`;
    flags.push(
      flag(
        "danger",
        "EIP712_DOMAIN_MISMATCH",
        `Signed with ${what} (copied from the requirements' extra) but ${tl}'s ${real}. The signature is internally consistent, yet the token contract computes a different digest, so transferWithAuthorization will revert with "invalid signature". Fix extra.${claimed.name !== onchain.name ? "name" : "version"} to '${claimed.name !== onchain.name ? onchain.name : onchain.version}' and re-sign.`,
      ),
    );
    fields.push(field("Recovered signer", checksumAddress(from), "address", "matches from, but only under the wrong domain"));
    return {
      flags,
      phrase: `Signature will be rejected on-chain: signed with ${what} but ${tl}'s ${real}.`,
      fields,
      hit: { domain: claimed, token, recovered: from },
    };
  }
  if (domainsDiffer && onchainOk) {
    flags.push(flag("ok", "SIG_VALID", `Signature valid: recovers to ${short(from)} under ${tl}'s on-chain domain.`));
    flags.push(
      flag(
        "warn",
        "EXTRA_DOMAIN_WRONG",
        `The requirements advertise extra.name/version '${extraName}'/'${extraVersion}', but ${tl}'s on-chain domain is '${onchain.name}'/'${onchain.version}'. This client ignored extra and signed correctly; clients that trust extra will produce signatures the contract rejects.`,
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
  const hit = searchDomains(
    domainCandidates(chainId, asset, ctx.extra),
    TRANSFER_WITH_AUTHORIZATION,
    "TransferWithAuthorization",
    message,
    sig,
    from,
  );
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
          `Signature was made for chainId ${asText(hd.chainId)} (${chainName(Number(hd.chainId))}) but this payment is on ${net?.name} (chainId ${chainId}). It will not verify on ${net?.name}.`,
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
        flags.push(
          flag(
            "warn",
            "EXTRA_DOMAIN_WRONG",
            `The requirements' extra says '${claimed.name}'/'${claimed.version}', but the signature (correctly) used '${hd.name}'/'${hd.version}'.`,
          ),
        );
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
