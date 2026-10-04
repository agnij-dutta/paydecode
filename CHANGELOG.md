# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-05

### Added

- `decode()` and `detect()`: auto-detect and explain agent-payment artifacts pasted as bare values, `Header: value`, `curl -H` lines, raw JSON, whole HTTP requests or responses, SD-JWT chains, or base64/base58 Solana transactions.
- x402 v1 and v2: PaymentRequired, PaymentPayload, SettleResponse, VerifyResponse, facilitator `/verify` `/settle` bodies, `/supported`, plus MCP `_meta` and A2A metadata wrappers.
- EIP-3009 verification with EIP-712 domain diagnosis (wrong name, version, chain or token), validity window, `payTo` and amount cross-checks.
- Permit2 (exact and upto) with nested EIP-712 recovery and x402 proxy spender checks.
- Solana exact payments: wire-format parser, instruction explanations, payer ed25519 verification, associated-token-account destination check, CU price cap and fee payer safety checks.
- AP2 v0.2 SD-JWT mandate chains: disclosure resolution, ES256 hop verification via `cnf.jwk`, `sd_hash` binding, open-vs-closed constraint cross-checks, checkout hash verification.
- AP2 v0.1 Intent, Cart and Payment mandates, and the AP2 x x402 credential bundle (nonce = keccak256(chain)).
- MPP challenges, credentials and receipts; ACP delegate payment, allowance, vault token and payment data; Visa TAP / RFC 9421 `Signature-Input`.
- `paydecode` CLI with `--json`, `--now`, `--strict` and color output.
- Web app (`web/`) for paste-and-read decoding in the browser.
