# paydecode

**jwt.io for agent payments.** Paste any agent-payment artifact and get a plain-English explanation of what it authorizes, plus specific, actionable risk flags.

```
$ paydecode "$(cat bundle.json)"

AP2 x x402 payment credential

  AP2 x402 credential that authorizes 0xf39F…2266 to pay 199.00 USDC on Base Sepolia to
  0x7099…79C8, valid until 28 Apr 2026. Signature will be rejected on-chain: signed with name
  'USD Coin' but Base Sepolia USDC's domain name is 'USDC'. Its nonce binds it to the AP2
  mandate chain.

  [DANGER] Signed with name 'USD Coin' but Base Sepolia USDC's domain name is 'USDC'. USDC's
           contract hashes the real domain, so transferWithAuthorization will revert with
           "invalid signature". Re-sign with name 'USDC'.
  [OK]     EIP-3009 nonce equals keccak256(payment_mandate_chain), so this payment can only be
           the one the mandate chain authorized, and only once.
  ...
```

Runs entirely offline, in Node or the browser. Runtime dependencies are only `@noble/hashes`, `@noble/curves` and `@scure/base`.

## What it decodes

| Format                                                                                      | Recognized as                                    | Verification depth                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **x402 v1 / v2 PaymentRequired** (`PAYMENT-REQUIRED` header, v1 402 body)                   | `x402.payment-required`                          | Prices with real decimals, network names, flags wrong EIP-712 domain in `extra`, unknown assets, tokens without EIP-3009, missing Solana fee payer                                                                                                                                                                                                                                                                                             |
| **x402 PaymentPayload** (`X-PAYMENT`, `PAYMENT-SIGNATURE`)                                  | `x402.payment-payload`                           | Full, see the scheme rows below. Cross-checks against `accepted` (v2) or `paymentRequirements` (facilitator body)                                                                                                                                                                                                                                                                                                                              |
| exact / EVM / **EIP-3009**                                                                  | inside the payload                               | Recovers the signer from the EIP-712 digest and compares to `from`. If it fails, searches known USDC domains to say _why_: wrong domain name or version, wrong chain, wrong token, or a genuinely bad signature. Validity window vs now, `to` vs `payTo`, value vs required amount                                                                                                                                                             |
| exact / upto / EVM / **Permit2**                                                            | inside the payload                               | Nested EIP-712 signer recovery, spender must be the x402 Permit2 proxy, witness recipient vs `payTo`, token vs asset, deadline, wrong-chain detection                                                                                                                                                                                                                                                                                          |
| exact / **SVM** (base64 versioned tx)                                                       | inside the payload, or `svm.transaction` bare    | Own wire-format parser (legacy and v0). Lists every instruction in English, verifies payer ed25519 signatures, checks the destination is `payTo`'s associated token account, CU price cap of 5,000,000 microlamports, fee payer vs `extra.feePayer`, fee payer acting as transfer authority, unknown programs, approvals                                                                                                                       |
| x402 **SettleResponse / VerifyResponse**                                                    | `x402.settle-response`, `x402.verify-response`   | Error reasons explained in English                                                                                                                                                                                                                                                                                                                                                                                                             |
| x402 facilitator **`/verify` `/settle` bodies**, **`/supported`**                           | `x402.facilitator-request`, `x402.supported`     | Payload checked against `paymentRequirements`, and the two are compared                                                                                                                                                                                                                                                                                                                                                                        |
| **MCP `_meta`** and **A2A metadata** wrappers, JSON-RPC envelopes                           | the inner artifact, or `container`               | Unwrapped automatically                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **AP2 v0.2 SD-JWT mandate chains** (`~~`-joined)                                            | `ap2.mandate-chain`                              | Splits hops, resolves `...` and `_sd` disclosure digests, renders each mandate by `vct`, verifies ES256 hop signatures with the previous hop's `cnf.jwk`, verifies `sd_hash` / `issuer_jwt_hash`, checks `checkout_hash` against the embedded checkout JWT, flags expired or unbound hops, and cross-checks that the closed mandate is within the open mandate's constraints. The root issuer signature is reported as "not verified (no key)" |
| **AP2 v0.1** Intent / Cart / Payment mandates                                               | `ap2.v01.*`                                      | Rendered and flagged (no expiry, any merchant, no cart confirmation, missing merchant or user authorization). Embedded x402 objects are decoded as children                                                                                                                                                                                                                                                                                    |
| **AP2 x x402 credential bundle** `{payment_mandate_chain, payment_nonce, eip_3009_payload}` | `ap2.x402-credential`                            | EIP-3009 nonce must equal keccak256(chain), `payment_nonce` vs the agent-signed KB nonce, amount vs the closed mandate, plus the full EIP-3009 check (network inferred from the signature domain)                                                                                                                                                                                                                                              |
| **MPP** `WWW-Authenticate: Payment`, `Authorization: Payment`, `Payment-Receipt`            | `mpp.challenge`, `mpp.credential`, `mpp.receipt` | Decodes the challenge and its `request`, expiry, body digest binding. Proofs are "not verified (no key)"                                                                                                                                                                                                                                                                                                                                       |
| **ACP** delegate payment request, allowance, vault token, checkout payment data             | `acp.*`                                          | Allowance in English, expiry, flags raw card numbers (PCI data) and risk signals                                                                                                                                                                                                                                                                                                                                                               |
| **Visa TAP** / RFC 9421 `Signature-Input`                                                   | `visa-tap.signature`                             | Covered components, tag meaning, window length, nonce. Signature "not verified (no key)"                                                                                                                                                                                                                                                                                                                                                       |
| plain **JWT**                                                                               | `jwt`                                            | Header and claims, inner payment schemas decoded                                                                                                                                                                                                                                                                                                                                                                                               |
| anything else                                                                               | `unknown`                                        | Useful hints: "this is base64 JSON but no known schema matched; here's the JSON", "that's a bare signature", and so on                                                                                                                                                                                                                                                                                                                         |

Input can be a bare value, `Header: value`, a `curl -H '...'` line, raw JSON, a whole HTTP request or response (headers plus body), an SD-JWT chain, or a base64/base58 Solana transaction.

## CLI

```
paydecode <blob>            decode a header value, JSON, SD-JWT, base64 tx...
paydecode <file>            decode the contents of a file
echo <blob> | paydecode     read from stdin
curl -si https://api.example.com/paid | paydecode

Options
  --json         print the decoded result as JSON
  --now <unix>   evaluate expiry against this unix time instead of now
  --no-color     disable ANSI colors (also honors NO_COLOR)
  --strict       exit with code 3 if any DANGER flag is raised
```

Exit codes: `0` decoded, `1` unrecognized input, `2` usage error, `3` danger flag with `--strict`.

## Library

```ts
import { decode, detect } from "paydecode";

const d = decode("PAYMENT-SIGNATURE: eyJ4NDAyVmVyc2lvbiI6Mi...", { now: 1740672100 });
d.kind; // "x402.payment-payload"
d.summary; // "Authorizes 0x857b…6b66 to pay 0.01 USDC on Base Sepolia to 0x2096…287C, valid for 65 seconds starting 27 Feb 2025. Signature valid."
d.flags; // [{ level: "ok", code: "SIG_VALID", message: "Signature valid: recovers to ..." }, ...]
d.sections; // titled groups of { label, value, note?, kind? } for display
d.raw; // the decoded JSON

detect("X-PAYMENT: eyJ..."); // { kind: "x402.payment-payload", header: "x-payment", encoding: "base64-json" }
```

`decode` never throws. It returns `Decoded | Unrecognized` (see `src/types.ts`). Flags are sorted danger, warn, info, ok, and every flag has a stable `code` so UIs and CI can match on it.

Nested artifacts (the mandate chain inside an AP2 bundle, the x402 requirements inside an AP2 v0.1 cart) are in `children`, each with its own flags. When several artifacts are pasted together (an HTTP response with a header and a body, an A2A message with requirements and a payload), the result has `kind: "container"`, one child per artifact, and the container repeats the children's danger and warn flags prefixed with `[n]`.

Lower-level helpers are exported too: `parseTransaction`, `associatedTokenAddress`, `parseChain`, `parseSdToken`, `verifyEs256`, `sdHash`, `typedDataHash`, `recoverAddress`, `checksumAddress`, `networkInfo`, `EVM_TOKENS`, `SPL_TOKENS`.

### Public types

`src/types.ts` is unchanged from the original contract. Additions live outside it: the `detect()` return type `Detection` is exported from `src/detect.ts`, and `Decoded.kind` takes the values listed in the table above.

## Why

AI agents are starting to spend money through x402, AP2, MPP, ACP and Visa TAP. Every one of those protocols moves authority around as an opaque blob: a base64 header, an SD-JWT chain, a partially signed Solana transaction. When something goes wrong, the people debugging it (and the people approving it) can't read what they're looking at.

The bugs are real and quiet. AP2's own x402 sample signs Base Sepolia USDC with the EIP-712 domain name "USD Coin", but the deployed contract's name is "USDC", so every signature it produces is rejected on-chain with a bare "invalid signature". Nothing in the payload tells you that. paydecode does: it recovers the signer, notices it only matches under the wrong domain, and names the exact field to fix.

The goal is the same as jwt.io: paste the thing, understand the thing, in one sentence, before you trust it.

## Development

```
npm run build -w paydecode   # tsup for JS, tsc for .d.ts (tsup's dts plugin doesn't support TypeScript 7)
npm test -w paydecode        # vitest
npx tsx scripts/gen-fixtures.mts   # regenerate test/fixtures/ap2-x402-bundle.json
```

Fixtures: `test/fixtures/fixtures.json` (verbatim x402 and AP2 artifacts), `ap2-checkout-chain.txt` (verbatim from the AP2 docs), `ap2-x402-bundle.json` (the AP2 sample's credential bundle reproduced with its own default keys). Solana transactions, Permit2 payloads and extra AP2 chains are generated inside the tests with `@solana/web3.js`, `viem` and `@noble/curves`.

## License

MIT
