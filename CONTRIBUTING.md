# Contributing to paydecode

Thanks for helping. The most valuable contributions are **real artifacts that paydecode gets wrong** and **decoders for new agent-payment formats**.

## Setup

Node 20.19 or newer (Node 22.6+ to regenerate fixtures).

```sh
git clone https://github.com/agnij-dutta/paydecode.git
cd paydecode
npm ci
```

| Command (repo root) | What it does |
|---|---|
| `npm test` | Library tests (vitest) |
| `npm run lint` | ESLint on the library and the web app |
| `npm run format:check` | Prettier check (`npm run format -w paydecode` to fix) |
| `npm run typecheck` | `tsc` on both workspaces |
| `npm run build` | Library (`tsup` + `tsc` declarations) and web app (`vite`) |
| `npm run dev` | Web app on http://localhost:5173 |
| `npm run paydecode -- <blob>` | Run the built CLI |
| `npm run fixtures -w paydecode` | Regenerate the synthetic fixtures (deterministic; Node 22.6+) |

CI runs all of these on Node 20 and 22, plus a gitleaks secret scan. Please run `npm run lint && npm run typecheck && npm test && npm run build` before opening a PR.

## Layout

```
packages/paydecode/          the library + CLI (published as "paydecode")
  src/types.ts               public result types: keep changes additive, the web app depends on them
  src/detect/                input unwrapping, sniffing, routing, wrapper walking, decode()/detect()
  src/x402/                  x402 requirements, payloads, responses
  src/evm/                   EIP-3009 (with EIP-712 domain diagnosis) and Permit2
  src/svm/                   Solana transaction parser and x402 exact/SVM analysis
  src/ap2/                   AP2 v0.2 SD-JWT chains, constraint checks, x402 bundle, v0.1 mandates
  src/mpp.ts, acp.ts, tap.ts MPP, ACP, Visa TAP
  src/crypto/                EIP-712 + secp256k1 recovery, SD-JWT + ES256
  src/core/                  formatting, network/token tables, result constructor
  src/cli.ts                 the only file allowed to import node: modules
  test/                      vitest suites; fixtures/ holds verbatim real artifacts
  scripts/gen-fixtures.mts   regenerates the synthetic fixtures deterministically
web/                         Vite + React app that imports the library source directly
docs/SPEC-NOTES.md           wire formats with links to the primary sources
```

## Adding a decoder for a new format

1. **Collect real artifacts first.** Copy them verbatim from the spec repo or a reference implementation into `test/fixtures/`, and note the source in the test. Never use real keys, card numbers or live payment blobs. Generate signed examples in-test with `viem`, `@noble/curves` or `@solana/web3.js` instead.
2. **Write the module** in `src/<format>.ts` (or `src/<format>/` if it needs more than about 400 lines). Start the file with a comment that links the spec section it implements. Export:
   - a shape test, `isMyFormat(o: Record<string, unknown>): boolean`, that is specific enough not to steal other formats' objects;
   - a decoder that returns `make(kind, title, summary, sections, flags, raw, children?)` from `src/core/result.ts`.
3. **Write the summary for a human.** It should be one or two sentences: who pays whom, how much (with real decimals), on what network, for how long, and whether the signature checks out. Look at the existing summaries for tone.
4. **Make flags specific and actionable.** Each flag has a stable `code` (`SCREAMING_SNAKE`), a level (`danger` means money goes wrong or a check failed, `warn` means risky but possibly intended, `info` is context, `ok` is a passed check), and a message that says what's wrong and what to do about it. If you can't verify something because a key is missing, say "not verified (no key)". Never report it as valid.
5. **Wire it in.** Strings with a recognizable prefix or header go in `decodeString` / `decodeHeaderValue` (`src/detect/classify.ts`, `src/detect/http.ts`); JSON objects go in `classifyObject`. Order matters: put more specific shapes first.
6. **Test it.** Cover every fixture, a tampered or invalid case, an expired case, and anything the summary claims. The fuzz test in `test/other.test.ts` must keep passing (the decoder must never throw).
7. **Document it.** Add a row to the format table in `packages/paydecode/README.md`, and a line under "Unreleased" in `CHANGELOG.md`.

Adding a token or network means adding a row to `src/core/networks.ts`. Say where the EIP-712 domain came from. On-chain verified rows use `source: "onchain"`.

## Style

- TypeScript strict, ESLint (typescript-eslint, type-aware) and Prettier, all clean.
- Library code must run in the browser: no `node:` imports and no `Buffer` outside `src/cli.ts`.
- Comments explain why (the spec rule or the gotcha), not what.
- No em dashes in code, docs or messages.

## Reporting a wrong decode

Open an issue with the (sanitized) input, what paydecode said, and what it should have said, ideally with a spec link. A failing test case is the best possible bug report.
