# paydecode

**jwt.io for agent payments.** Paste any agent-payment artifact (an x402 header, an AP2 mandate chain, an EIP-3009 or Permit2 authorization, a Solana payment transaction, an MPP, ACP or Visa TAP message) and get a plain-English explanation of what it authorizes, plus specific, actionable risk flags. It ships as a TypeScript library, a CLI and a web app. Everything is decoded locally.

```
$ paydecode --now 1777343000 packages/paydecode/test/fixtures/ap2-x402-bundle.json

AP2 x x402 payment credential  ap2.x402-credential

  AP2 x402 credential that authorizes 0xf39F…2266 to pay 199.00 USDC on Base Sepolia to
  0x7099…79C8, valid until 28 Apr 2026. Signature will be rejected on-chain: signed with name 'USD
  Coin' but Base Sepolia USDC's domain name is 'USDC'. Its nonce binds it to the AP2 mandate
  chain.

  [DANGER]  Signed with name 'USD Coin' but Base Sepolia USDC's domain name is 'USDC'. USDC's
           contract hashes the real domain, so transferWithAuthorization will revert with
           "invalid signature". Re-sign with name 'USDC'. EIP712_DOMAIN_MISMATCH
  [WARN]    The closed mandate has no on-chain payee_address, so nothing ties the recipient
           0x7099…79C8 to the mandate's payee Demo Merchant (merchant_1). (The AP2 sample falls
           back to a default merchant wallet.) AP2_PAYEE_UNBOUND
  [INFO]    The artifact doesn't name the token; the signature's EIP-712 domain identifies it as
           Base Sepolia USDC (0x036C…CF7e). ASSET_INFERRED
  [OK]      EIP-3009 nonce equals keccak256(payment_mandate_chain), so this payment can only be
           the one the mandate chain authorized, and only once. AP2_NONCE_BOUND
  [OK]      payment_nonce matches the nonce the agent signed into the closed mandate. AP2_KB_NONCE_OK
  [OK]      On-chain amount matches the closed mandate ($199.00 USD as 6-decimal USDC). AP2_AMOUNT_MATCHES
  ...
```

That is real CLI output, captured from this repo. The input is the credential bundle that AP2's own `x402_credentials_provider_mcp` sample produces, reproduced with the sample's default keys.

## Why

AI agents now spend money through x402, AP2, MPP, ACP and Visa TAP, and every one of them moves spending authority around as an opaque blob: a base64 header, a `~~`-joined SD-JWT chain, a partially signed Solana transaction. When a payment fails or looks wrong, the people debugging or approving it can't read what they're holding.

The bugs are real and quiet. AP2's x402 sample signs Base Sepolia USDC with the EIP-712 domain name "USD Coin", but the deployed contract's name is "USDC", so every signature it produces reverts on-chain with a bare "invalid signature" and nothing in the payload says why. paydecode recovers the signer, notices it only matches under the wrong domain, and names the exact field to fix.

## Quickstart

Requires Node 20 or newer.

```sh
git clone https://github.com/agnij-dutta/paydecode.git
cd paydecode
npm ci
npm run build
npm test

# decode the demo artifact above
npm run paydecode -- --now 1777343000 packages/paydecode/test/fixtures/ap2-x402-bundle.json

# decode anything: a header, JSON, an SD-JWT chain, a base64 Solana transaction
npm run paydecode -- "X-PAYMENT: eyJ4NDAyVmVyc2lvbiI6MSwic2NoZW1lIjoiZXhhY3QiLCJuZXR3b3JrIjoiYmFzZS1zZXBvbGlh..."

# the web app (paste box, two-pane explanation), at http://localhost:5173
npm run dev
```

## Usage

### CLI

```
paydecode <blob>            decode a header value, JSON, SD-JWT, base64 tx...
paydecode <file>            decode the contents of a file
echo <blob> | paydecode     read from stdin
curl -si https://api.example.com/paid | paydecode
```

| Flag | Meaning |
|---|---|
| `--json` | Print the full `Decoded` result as JSON |
| `--now <unix>` | Judge expiry against this unix time (seconds) instead of the clock |
| `--no-color` / `--color` | Force ANSI colors off or on (default: on for a TTY) |
| `--strict` | Exit with code 3 if any DANGER flag is raised, for CI gates |
| `-h`, `--help` | Show help |

Exit codes: `0` decoded, `1` unrecognized input, `2` usage error, `3` danger flag under `--strict`.

| Env var | Meaning |
|---|---|
| `NO_COLOR` | Disable ANSI colors (the [no-color.org](https://no-color.org) convention) |

No other configuration exists. There are no API keys and no network calls, so there is no `.env` file.

### Library

```ts
import { decode, detect } from "paydecode";

const d = decode("PAYMENT-SIGNATURE: eyJ4NDAyVmVyc2lvbiI6Mi...", { now: 1740672100 });
d.summary; // "Authorizes 0x857b…6b66 to pay 0.01 USDC on Base Sepolia to 0x2096…287C, valid for 65 seconds starting 27 Feb 2025. Signature valid."
d.flags;   // [{ level: "ok", code: "SIG_VALID", message: "..." }, ...]
```

| Export | Description |
|---|---|
| `decode(input, { now? })` | Decode any supported artifact. Returns `Decoded \| Unrecognized` and never throws |
| `detect(input)` | `{ kind, header?, encoding? }` without the explanation |
| `parseTransaction(bytes)` | Parse a legacy or v0 Solana transaction |
| `associatedTokenAddress(owner, mint, tokenProgram?)` | Derive an SPL associated token account |
| `parseChain(chain)`, `parseSdToken(token)` | Split and parse SD-JWT delegation chains, resolving disclosures |
| `verifyEs256(jwt, jwk)`, `sdHash(s, alg?)` | ES256 verification and SD-JWT hashing |
| `typedDataHash(domain, types, primaryType, message)`, `recoverAddress(digest, sig)`, `checksumAddress(addr)` | EIP-712 hashing (nested structs) and signer recovery |
| `networkInfo(id)`, `EVM_TOKENS`, `SPL_TOKENS` | Network names and known payment tokens with their EIP-712 domains |
| Types: `Decoded`, `Unrecognized`, `Section`, `Field`, `Flag`, `FlagLevel`, `DecodeOptions`, `Detection` | The result contract |

The full list of supported formats, what each `kind` means and how deeply each is verified is in [packages/paydecode/README.md](packages/paydecode/README.md).

## How it works

```
input string
   │
   ├─ unwrap: "Header: value", curl -H, a whole HTTP request/response, quotes
   │
   ├─ sniff:  JSON │ base64/base64url JSON │ SD-JWT (~ and ~~) │ JWT │ "Payment ..." auth-params
   │          │ RFC 9421 Signature-Input │ base64/base58 Solana transaction
   │
   ├─ classify by shape ─────────► x402 · AP2 v0.2 / v0.1 · AP2 x x402 bundle · MPP · ACP · TAP
   │   (walks MCP _meta, A2A metadata, JSON-RPC wrappers when nothing matches at the top level)
   │
   ├─ analyze: EIP-712 signer recovery + domain search · Permit2 nested EIP-712 · Solana tx parser
   │           + ed25519 · SD-JWT disclosures, ES256 hops, sd_hash · mandate constraint checks
   │
   └─ Decoded { kind, title, summary, flags[], sections[], raw, children? }
```

Each protocol lives in its own module under `packages/paydecode/src/` (`x402/`, `evm/`, `svm/`, `ap2/`, `mpp.ts`, `acp.ts`, `tap.ts`). Shared crypto is in `crypto/` and shared formatting and network tables are in `core/`. `detect/` owns the sniffing and routing.

The most involved check is EIP-3009 signature diagnosis. The library first recovers the signer under the domain the requirements claim, then under the token's real on-chain domain. If neither matches `from`, it tries every known token domain (name and version variants, other chains, other tokens) using a fast path: `s·R/r` is computed once per signature, so each candidate digest costs one fixed-base multiplication. A match under the wrong domain becomes a precise message ("signed with name 'USD Coin' but Base Sepolia USDC's domain name is 'USDC'"). No match at all means the fields were edited after signing, or a different key signed them.

Runtime dependencies are `@noble/hashes`, `@noble/curves` and `@scure/base`. The library has no Node built-ins, so the web app imports the same code in the browser.

Decode times, measured 2026-10-05 on an Apple M4 with Node 22.14.0, built `dist/`, mean of 50 warm runs:

| Input | Time |
|---|---|
| x402 v2 payment, valid signature | 1.2 ms |
| x402 v2 payment, tampered (full domain search) | 19.6 ms |
| AP2 2-hop SD-JWT chain | 1.2 ms |
| AP2 x x402 bundle (domain mismatch) | 3.4 ms |

## Security model and limitations

paydecode explains and checks. It does not authorize, settle or simulate anything. Read "Signature valid" as "this signature is internally consistent and recovers to `from` under the named domain", not as "this payment will succeed".

- **No chain state.** It never calls an RPC, so it can't see balances, allowances, Permit2 approvals, used nonces, smart-wallet (EIP-1271/6492) signatures or whether a payment already settled. Token domains come from a built-in table (USDC rows checked on-chain on 2026-10-04); an unknown token shows "unknown asset" rather than a guess.
- **Keys it doesn't have stay unverified.** The AP2 root issuer signature, merchant checkout JWTs, MPP proofs, ACP vault tokens and Visa TAP signatures are reported as "not verified (no key)". Delegated AP2 hops are verified, because the key travels inside the chain (`cnf.jwk`).
- **Stateful constraints are skipped.** AP2 budgets, recurrence counts and checkout references need history or other mandates, so they are listed as "not checkable offline".
- **Solana address lookup tables** can't be resolved offline. Accounts loaded from them are shown as table entries.
- **Pasting is a disclosure.** The library and the web app decode locally and send nothing anywhere, but an x402 authorization is a bearer instrument until it expires. Don't paste live, unexpired payment blobs into tools you don't control. ACP requests can contain raw card numbers; paydecode flags them and masks them in the explanation, though `raw` (and `--json`) still contains exactly what you pasted.
- **Heuristics are heuristics.** Thresholds such as "window longer than an hour" and the 8-minute TAP window are conventions taken from reference implementations, not spec rules.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Prior art

- [jwt.io](https://jwt.io): the paste-and-read model this copies, for plain JWTs. It doesn't know payment semantics, EIP-712 or SD-JWT delegation chains.
- [Solana Explorer transaction inspector](https://explorer.solana.com/tx/inspector) and EVM explorers' input decoders: they decode transactions, but not x402 requirements, so they can't say whether a transfer matches what the server asked for.
- Wallet transaction simulators (for example [Tenderly](https://tenderly.co)): they show real state changes, but need an RPC, a transaction rather than an off-chain authorization, and they don't speak AP2, MPP or ACP.
- x402 facilitators' `/verify` endpoint: authoritative for one network, but it returns an error code such as `invalid_exact_evm_payload_signature`, not a reason.

paydecode adds one place that understands all of these agent-payment formats, cross-checks them against each other (requirements vs payload, open vs closed mandate, mandate vs on-chain nonce), and explains the result in a sentence.

## Roadmap

- Optional RPC mode: balances, allowances, nonce-used checks and EIP-1271/6492 smart-wallet signatures.
- Pluggable trust roots: verify AP2 root issuers, merchant checkout JWTs and Visa TAP signatures when the caller supplies keys or a registry URL.
- More x402 schemes: `upto` on SVM, `batch-settlement`, `auth-capture`, and the Aptos, Sui, Stellar and other exact mechanisms.
- Resolve Solana address lookup tables when an RPC is available.
- A larger corpus of real-world artifacts as fixtures, contributed by facilitators and agent builders.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). It covers setup, tests and how to add a decoder for a new format.

## License

[MIT](LICENSE)

## Author

Agnij Dutta ([@0xholmesdev](https://x.com/0xholmesdev))
