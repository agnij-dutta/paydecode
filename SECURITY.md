# Security policy

paydecode reads payment authorizations, so mistakes in it can mislead people about money. Security reports are welcome and taken seriously.

## Reporting a vulnerability

Please report privately through GitHub's **[private vulnerability reporting](https://github.com/agnij-dutta/paydecode/security/advisories/new)** ("Report a vulnerability" on the Security tab). Don't open a public issue for security problems.

Include the input that triggers the problem, what paydecode reported, and what it should have reported. You'll get an acknowledgement within a few days. Fixes are released with credit unless you prefer otherwise.

## In scope

- **False assurance:** paydecode reports a signature, binding or constraint check as valid (`ok`) when it isn't, or misses a `danger` condition it claims to check (for example a wrong `payTo`, an overpayment, a non-proxy Permit2 spender, a broken `sd_hash`).
- **Misleading explanations:** a summary that misstates who pays whom, how much, on which network, or until when.
- **Crashes or hangs** on crafted input (the decoder is meant to never throw, and to stay fast on hostile input).
- **Data leaks:** the library or web app sending pasted input anywhere, or failing to mask data it claims to mask.
- **Supply chain** issues in the published package or the CI workflow.

## Known non-goals

These are documented limitations, not vulnerabilities (see the README's "Security model and limitations"):

- No on-chain state: balances, allowances, used nonces, smart-wallet (EIP-1271/6492) signatures and settlement status are not checked.
- Signatures whose keys aren't in the artifact (the AP2 root issuer, merchant checkout JWTs, MPP proofs, Visa TAP) are reported as "not verified (no key)".
- Stateful AP2 constraints (cumulative budget, recurrence, checkout reference) are not evaluated offline.
- Heuristic thresholds (long validity windows, the 8-minute TAP window) are conventions, not guarantees.
