// x402 message shape tests and error-reason glossary.
// Specs: https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md (and -v1.md)
import { isRecord } from "../core/encoding.js";
import { asText } from "../core/format.js";

type Obj = Record<string, unknown>;

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

export const ERROR_GLOSSARY: Record<string, string> = {
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

export const EXTENSION_GLOSSARY: Record<string, string> = {
  bazaar: "discovery metadata for the x402 Bazaar",
  "sign-in-with-x": "Sign-In-With-X: proves wallet ownership to log in",
  payment_identifier: "idempotency key for the payment",
  "offer-and-receipt": "signed offer and receipt objects",
  builder_code: "attribution code for the integrator",
  "extension-auth-hints": "hints about which auth the server accepts",
  eip2612GasSponsoring: "EIP-2612 permit so the facilitator can approve Permit2 gaslessly",
  erc20ApprovalGasSponsoring: "pre-signed ERC-20 approval the facilitator submits for Permit2",
};
