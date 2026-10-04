// x402 PaymentPayload (X-PAYMENT / PAYMENT-SIGNATURE): dispatches to the scheme analyzers and
// cross-checks against `accepted` or the facilitator's paymentRequirements.
import { decodeBase64, isRecord } from "../core/encoding.js";
import { asText, field, flag, section, short } from "../core/format.js";
import { networkInfo } from "../core/networks.js";
import { make } from "../core/result.js";
import type { Analysis, PaymentContext } from "../evm/context.js";
import { analyzeEip3009 } from "../evm/eip3009.js";
import { analyzePermit2 } from "../evm/permit2.js";
import { analyzeSvmTransaction } from "../svm/analyze.js";
import type { Decoded, Flag, Section } from "../types.js";
import { describeRequirement, extensionsSection, requirementContext, resourceFields, resourceText } from "./requirements.js";

type Obj = Record<string, unknown>;

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
