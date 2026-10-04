// AP2 v0.2 delegation chains: SD-JWT hops joined by "~~" (draft-gco-oauth-delegate-sd-jwt-00).
// Each hop after the first is verified with the previous hop's cnf.jwk and bound to it by sd_hash.
// Spec: https://github.com/google-agentic-commerce/AP2/blob/main/docs/ap2/payment_mandate.md
import { checkCheckoutConstraints, checkPaymentConstraints } from "./constraints.js";
import { renderMandate } from "./mandates.js";
import type { MandateView } from "./mandates.js";
import { isRecord } from "../core/encoding.js";
import { asText, field, flag, listJoin, relative, section, sentence, short, timeField, toUnix } from "../core/format.js";
import { make } from "../core/result.js";
import { findCnfJwk, parseChain, sdHash, verifyEs256 } from "../crypto/sdjwt.js";
import type { SdToken } from "../crypto/sdjwt.js";
import type { Decoded, Field, Flag, Section } from "../types.js";

type Obj = Record<string, unknown>;

// ---------------------------------------------------------------- SD-JWT chains

export const mandatesOf = (t: SdToken): Obj[] =>
  Array.isArray(t.resolved.delegate_payload) ? t.resolved.delegate_payload.filter(isRecord) : [];
export const primaryMandate = (t: SdToken): Obj | undefined => mandatesOf(t).find((m) => typeof m.vct === "string") ?? mandatesOf(t)[0];

export interface ChainResult {
  decoded: Decoded;
  hops: SdToken[];
  closed?: Obj;
}

export function decodeSdJwtChain(input: string, now: number): ChainResult | undefined {
  const hops = parseChain(input);
  if (!hops || !hops.length) return undefined;
  const flags: Flag[] = [];
  const sections: Section[] = [];
  const views: MandateView[] = [];
  let sigVerified = 0;
  let sigUnchecked = 0;
  let sigBad = 0;
  let bindOk = 0;
  let bindBad = 0;
  let sdBad = 0;

  hops.forEach((hop, i) => {
    const label = `Hop ${i + 1}`;
    const h = hop.jwt.header;
    const p = hop.jwt.payload;
    const typ = asText(h.typ, "");
    const isLast = i === hops.length - 1;
    const fields: Field[] = [
      field("JWT typ", typ || "(none)", "code"),
      field("Algorithm", asText(h.alg, "(none)"), "code", h.kid ? `kid ${asText(h.kid)}` : undefined),
    ];
    if (h.alg !== "ES256")
      flags.push(
        flag(
          h.alg === "none" ? "danger" : "warn",
          "HOP_ALG",
          `${label}: alg is '${asText(h.alg)}'; AP2 mandates are ES256.${h.alg === "none" ? " An unsigned mandate proves nothing." : ""}`,
        ),
      );

    // Signature
    if (i === 0) {
      const jwk = isRecord(h.jwk) ? h.jwk : undefined;
      if (jwk) {
        const ok = verifyEs256(hop.jwt, jwk);
        fields.push(
          field(
            "Signature",
            ok ? "valid (key embedded in header)" : "INVALID",
            "text",
            "an embedded key only proves self-consistency, not who issued it",
          ),
        );
        if (ok) sigVerified++;
        else {
          sigBad++;
          flags.push(flag("danger", "HOP_SIG_INVALID", `${label}: ES256 signature does not verify with the key in its own header.`));
        }
      } else {
        sigUnchecked++;
        fields.push(
          field(
            "Signature",
            "not verified (no key)",
            "text",
            `issuer key${h.kid ? ` '${asText(h.kid)}'` : ""} isn't included; check it against the agent provider's published key`,
          ),
        );
        flags.push(
          flag(
            "info",
            "ROOT_SIG_UNCHECKED",
            `${label}: the root issuer signature${h.kid ? ` (kid '${asText(h.kid)}')` : ""} wasn't verified because the issuer's public key isn't in the artifact.`,
          ),
        );
      }
    } else {
      const prev = hops[i - 1];
      const jwk = findCnfJwk(prev);
      if (!jwk) {
        sigUnchecked++;
        fields.push(field("Signature", "not verified (previous hop has no cnf key)", "text"));
        flags.push(
          flag(
            "danger",
            "HOP_UNBOUND",
            `${label}: hop ${i} carries no cnf key, so nothing binds this hop to whoever was delegated. Anyone holding hop ${i} could have appended it.`,
          ),
        );
      } else {
        const ok = verifyEs256(hop.jwt, jwk);
        fields.push(field("Signature", ok ? `valid (signed by hop ${i}'s cnf key)` : `INVALID under hop ${i}'s cnf key`, "text"));
        if (ok) sigVerified++;
        else {
          sigBad++;
          flags.push(
            flag(
              "danger",
              "HOP_SIG_INVALID",
              `${label}: ES256 signature does not verify with the cnf key delegated in hop ${i}. Either it was signed by a different key or its payload was edited.`,
            ),
          );
        }
      }
      // sd_hash / issuer_jwt_hash binding
      const alg = prev.jwt.payload._sd_alg ?? "sha-256";
      if (typeof p.sd_hash === "string") {
        const expected = sdHash(prev.sdJwt, alg);
        if (expected === p.sd_hash) {
          bindOk++;
          fields.push(field("sd_hash", p.sd_hash, "hash", `matches sha256 of hop ${i} (including the trailing ~)`));
        } else {
          bindBad++;
          fields.push(field("sd_hash", p.sd_hash, "hash", `does NOT match hop ${i} (expected ${short(expected, 8, 4)})`));
          flags.push(
            flag(
              "danger",
              "SD_HASH_MISMATCH",
              `${label}: sd_hash doesn't match hop ${i}. This hop was signed over a different version of the previous mandate (disclosures added, removed or edited).`,
            ),
          );
        }
      } else if (typeof p.issuer_jwt_hash === "string") {
        const expected = sdHash(prev.jwt.raw, alg);
        if (expected === p.issuer_jwt_hash) {
          bindOk++;
          fields.push(field("issuer_jwt_hash", p.issuer_jwt_hash, "hash", `matches hop ${i}'s issuer JWT`));
        } else {
          bindBad++;
          flags.push(flag("danger", "SD_HASH_MISMATCH", `${label}: issuer_jwt_hash doesn't match hop ${i}'s issuer JWT.`));
        }
      } else {
        bindBad++;
        flags.push(
          flag(
            "danger",
            "HOP_NO_SD_HASH",
            `${label}: no sd_hash or issuer_jwt_hash, so this hop isn't bound to the mandate it claims to extend.`,
          ),
        );
      }
      if (!typ.startsWith("kb+sd-jwt")) flags.push(flag("warn", "HOP_TYP", `${label}: typ '${typ}' is not kb+sd-jwt / kb+sd-jwt+kb.`));
      if (p.aud !== undefined) fields.push(field("Audience", asText(p.aud)));
      if (p.nonce !== undefined) fields.push(field("Nonce", asText(p.nonce), "code"));
    }
    const jexp = toUnix(p.exp);
    const jiat = toUnix(p.iat);
    if (jiat !== undefined) fields.push(timeField("JWT issued", jiat, now, p.iat));
    if (jexp !== undefined) {
      fields.push(timeField("JWT expires", jexp, now, p.exp));
      if (jexp <= now) flags.push(flag("danger", "HOP_EXPIRED", `${label}: the JWT expired ${relative(jexp, now)}.`));
    }
    fields.push(field("Disclosures", `${hop.disclosures.length} revealed${hop.undisclosed ? `, ${hop.undisclosed} kept hidden` : ""}`));
    sdBad += hop.problems.length;
    for (const problem of hop.problems)
      flags.push(
        flag(
          "danger",
          "SD_JWT_MALFORMED",
          `${label}: ${problem}. RFC 9901 says a verifier must reject this SD-JWT, so the claims shown for it can't be trusted.`,
        ),
      );
    const unused = hop.disclosures.filter((d) => !d.used);
    if (unused.length)
      flags.push(
        flag(
          "warn",
          "DISCLOSURE_UNUSED",
          `${label}: ${unused.length} disclosure(s) don't match any digest in the JWT. They were attached but are not covered by the signature, so ignore their contents.`,
        ),
      );

    const mandate = primaryMandate(hop);
    if (mandate) {
      const v = renderMandate(mandate, now, label);
      views.push(v);
      flags.push(...v.flags);
      const hasCnf = isRecord(mandate.cnf) || isRecord(hop.resolved.cnf);
      if (isLast && v.open && !hasCnf)
        flags.push(
          flag(
            "danger",
            "OPEN_MANDATE_UNBOUND",
            `${label}: open mandate has no cnf key, so it isn't bound to any agent. Whoever holds it can close it.`,
          ),
        );
      if (isLast && v.open && hasCnf)
        flags.push(
          flag(
            "info",
            "OPEN_MANDATE_PENDING",
            `${label}: this open mandate hasn't been closed yet. Only the holder of its cnf key can close it.`,
          ),
        );
      if (isLast && !v.open && hasCnf && hops.length > 1)
        flags.push(
          flag("warn", "TERMINAL_HAS_CNF", `${label}: the terminal (closed) hop carries a cnf claim; AP2 says terminal hops must not.`),
        );
      sections.push({ ...section(`${label}: ${v.label}`, [...v.fields, ...fields]), hop: i + 1 });
    } else {
      flags.push(flag("warn", "HOP_NO_MANDATE", `${label}: no delegate_payload mandate was disclosed.`));
      sections.push({ ...section(`${label}: SD-JWT`, [...fields, field("Claims", JSON.stringify(hop.resolved), "code")]), hop: i + 1 });
    }
  });

  // Cross-check consecutive open -> closed pairs
  const crossLines: string[] = [];
  let crossOk = true;
  let crossRan = false;
  for (let i = 0; i + 1 < hops.length; i++) {
    const a = primaryMandate(hops[i]);
    const b = primaryMandate(hops[i + 1]);
    if (!a || !b) continue;
    const va = asText(a.vct, "");
    const vb = asText(b.vct, "");
    let res: ReturnType<typeof checkPaymentConstraints> | undefined;
    if (va.startsWith("mandate.payment.open") && vb.startsWith("mandate.payment") && !vb.includes(".open."))
      res = checkPaymentConstraints(a, b);
    else if (va.startsWith("mandate.checkout.open") && vb.startsWith("mandate.checkout") && !vb.includes(".open."))
      res = checkCheckoutConstraints(a, b);
    if (!res) continue;
    crossRan = true;
    if (res.violations.length) {
      crossOk = false;
      for (const v of res.violations)
        flags.push(flag("danger", "MANDATE_CONSTRAINT_VIOLATION", `Hop ${i + 2} breaks hop ${i + 1}'s constraints: ${v}.`));
    } else if (res.checked.length) {
      flags.push(
        flag(
          "ok",
          "MANDATE_WITHIN_CONSTRAINTS",
          `Hop ${i + 2} stays within hop ${i + 1}'s constraints (checked ${listJoin(res.checked)}).`,
        ),
      );
    }
    if (res.skipped.length) flags.push(flag("info", "MANDATE_CONSTRAINTS_SKIPPED", `Not checkable offline: ${listJoin(res.skipped)}.`));
    crossLines.push(...res.checked.map((c) => `${c}: ok`), ...res.violations);
  }

  // Summary
  const kindWord = views.some((v) => v.vct.startsWith("mandate.checkout")) ? "checkout" : "payment";
  const parts: string[] = [];
  const openV = views.find((v) => v.open);
  const closedV = [...views].reverse().find((v) => !v.open);
  if (openV && closedV) {
    parts.push(
      `AP2 ${kindWord} mandate chain (${hops.length} hops): the user's open mandate ${kindWord === "checkout" ? "lets the agent " : "allows "}${openV.english || "unstated limits"}; the agent closed it to ${closedV.english}${crossRan ? (crossOk ? ", within those limits" : ", BREAKING those limits") : ""}.`,
    );
  } else if (openV) {
    parts.push(
      `AP2 open ${kindWord} mandate: lets the delegated agent ${kindWord === "payment" ? "pay with" : "check out with"} ${openV.english || "unstated limits"}.`,
    );
  } else if (closedV) {
    parts.push(`AP2 closed ${kindWord} mandate: ${closedV.english}.`);
  } else parts.push(`SD-JWT delegation chain with ${hops.length} hop(s).`);
  const sigBits: string[] = [];
  if (sigBad || bindBad || sdBad) sigBits.push(`${sigBad + bindBad + sdBad} signature/binding/SD-JWT check(s) FAILED`);
  else if (sigVerified || bindOk) sigBits.push(`${hops.length > 1 ? "agent signature and sd_hash binding verify" : "signature verifies"}`);
  if (sigUnchecked) sigBits.push("the root issuer signature isn't checked (no key)");
  const expired = flags.some((f) => f.code === "MANDATE_EXPIRED" || f.code === "HOP_EXPIRED");
  if (expired) sigBits.push("the mandate has expired");
  if (sigBits.length)
    parts.push(
      sentence(sigBits[0][0].toUpperCase() + sigBits[0].slice(1) + (sigBits.length > 1 ? `; ${sigBits.slice(1).join("; ")}` : "")),
    );

  sections.unshift(
    section("Chain", [
      field("Hops", asText(hops.length)),
      ...views.map((v, i) => ({ ...field(`Hop ${i + 1}`, v.label, "text", v.english), hop: i + 1 })),
      ...(crossLines.length
        ? [
            field(
              "Cross-check",
              crossOk ? "closed mandate is within the open mandate" : "VIOLATES the open mandate",
              "text",
              crossLines.join("; "),
            ),
          ]
        : []),
    ]),
  );
  const closed = [...hops]
    .reverse()
    .map(primaryMandate)
    .find((m) => m && !asText(m.vct, "").includes(".open."));
  return {
    decoded: make(
      "ap2.mandate-chain",
      `AP2 ${kindWord} mandate${hops.length > 1 ? " chain" : ""} (SD-JWT)`,
      parts.join(" "),
      sections,
      flags,
      hops.map((h) => ({ header: h.jwt.header, payload: h.resolved })),
    ),
    hops,
    closed,
  };
}
