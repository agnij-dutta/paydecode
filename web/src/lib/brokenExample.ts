import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { checksumAddress, typedDataHash } from "paydecode";
import { EXAMPLES } from "./examples";

/**
 * The demo "broken" payment: the x402 v2 fixture with accepted.extra.name changed to
 * "USD Coin", then signed the way a client that trusts `extra` would, i.e. under the
 * wrong EIP-712 domain. Base Sepolia USDC's on-chain name is "USDC", so the contract
 * computes a different digest and transferWithAuthorization reverts.
 *
 * Signed with a throwaway key derived from a public string (it holds nothing), with a
 * fresh validity window so the only real problem on screen is the domain mismatch.
 */
const DEMO_KEY = keccak_256(new TextEncoder().encode("paydecode public demo key: holds nothing, never fund it"));

const TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

const hex = (b: Uint8Array) => "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

function b64encode(s: string) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

function b64decode(s: string) {
  const bin = atob(s);
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

/** The fields of an x402 v2 PaymentPayload this demo reads or rewrites. */
interface PaymentPayloadV2 {
  accepted: { payTo: string; amount: string; asset: string; extra: { name: string; version: string } };
  payload?: unknown;
}

export function buildBrokenExample(nowSeconds = Math.floor(Date.now() / 1000)): string {
  const base = EXAMPLES.find((e) => e.id === "x402-v2-payment")!;
  const p = JSON.parse(b64decode(base.value)) as PaymentPayloadV2;
  p.accepted.extra.name = "USD Coin";

  const pub = secp256k1.getPublicKey(DEMO_KEY, false);
  const from = checksumAddress(hex(keccak_256(pub.slice(1)).slice(-20)));
  const nonce = hex(crypto.getRandomValues(new Uint8Array(32)));
  const auth = {
    from,
    to: p.accepted.payTo,
    value: p.accepted.amount,
    // Same 660 s window as the reference client (maxTimeoutSeconds + 10 minutes), shifted
    // forward so it stays valid for about ten minutes after you click the example.
    validAfter: String(nowSeconds - 60),
    validBefore: String(nowSeconds + 600),
    nonce,
  };
  const digest = typedDataHash(
    { name: p.accepted.extra.name, version: p.accepted.extra.version, chainId: 84532, verifyingContract: p.accepted.asset },
    TYPES,
    "TransferWithAuthorization",
    auth,
  );
  const rec = secp256k1.sign(digest, DEMO_KEY, { prehash: false, format: "recovered" });
  const sig = new Uint8Array(65);
  sig.set(rec.slice(1), 0);
  sig[64] = rec[0] + 27;

  p.payload = { signature: hex(sig), authorization: auth };
  return `PAYMENT-SIGNATURE: ${b64encode(JSON.stringify(p))}`;
}
