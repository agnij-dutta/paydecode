# Wire-format notes (researched 2026-10-04, primary sources)

Primary sources: [x402-foundation/x402](https://github.com/x402-foundation/x402), [google-agentic-commerce/AP2](https://github.com/google-agentic-commerce/AP2), [google-agentic-commerce/a2a-x402](https://github.com/google-agentic-commerce/a2a-x402), [agentic-commerce-protocol](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol), [visa/trusted-agent-protocol](https://github.com/visa/trusted-agent-protocol), [tempoxyz/mpp-specs](https://github.com/tempoxyz/mpp-specs).
Verbatim fixtures: `packages/paydecode/test/fixtures/fixtures.json`.

## x402: canonical repo MOVED
`github.com/coinbase/x402` is stale (HEAD 2026-04-21). Live: **`github.com/x402-foundation/x402`** (HEAD 2026-10-02). npm `@x402/core|evm|svm` 2.28.0. Legacy npm `x402` 1.2.0.

| | v1 | v2 |
|---|---|---|
| 402 requirements | JSON **body** `{x402Version:1, error?, accepts[]}` | **`PAYMENT-REQUIRED`** header, base64(JSON PaymentRequired); body arbitrary |
| client header | `X-PAYMENT` base64(JSON) | `PAYMENT-SIGNATURE` base64(JSON) |
| settle header | `X-PAYMENT-RESPONSE` | `PAYMENT-RESPONSE` |
| network | names (`base`, `base-sepolia`, `avalanche`, `avalanche-fuji`, `polygon`, `polygon-amoy`, `ethereum`, `sepolia`, `solana`, `solana-devnet`, `sei`, `iotex`, `abstract`, `peaq`, `story`, `educhain`, `skale-base-sepolia`, `megaeth`, `monad`, `stable`...) | CAIP-2 |
| amount | `maxAmountRequired` | `amount` |
| resource | flat per-requirement `resource, description, mimeType, outputSchema` | top-level `resource: {url, description?, mimeType?, serviceName?, tags?, iconUrl?}` |
| payload | `{x402Version:1, scheme, network, payload}` | `{x402Version:2, resource?, accepted: PaymentRequirements, payload, extensions?}` |

Encoding: standard base64 with padding over UTF-8 JSON (accept base64url too). Client version detection: `PAYMENT-REQUIRED` header present means v2, else body `x402Version===1`. Facilitator-only v2 header `EXTENSION-RESPONSES`.
MCP transport: `_meta["x402/payment"]`, `_meta["x402/payment-response"]`; payment-required result = `isError:true` + `structuredContent` PaymentRequired. A2A metadata keys: `x402.payment.status|required|payload|receipts[]`.

**v2 PaymentRequirements**: `scheme, network, amount (atomic string), asset (address/mint/ISO-4217), payTo (address or role like "merchant"), maxTimeoutSeconds:number, extra:object`. Reserved extra keys: `assetTransferMethod` (`eip3009` default | `permit2` | `erc7710`), `paymentFlow` (`authorization` default | `upfront` | `escrow`). EVM extra: `name`, `version` (EIP-712 domain). SVM extra: `feePayer`, `memo?`, `recentBlockhash?`, `lastValidBlockHeight?`.
**SettleResponse**: `success, errorReason?, errorMessage?, payer?, transaction ("" if none), network, amount? (upto), extensions?, extra?`. **VerifyResponse**: `isValid, invalidReason?, invalidMessage?, payer?`.
Facilitator: `/verify` `/settle` body `{x402Version, paymentPayload, paymentRequirements}`; `/supported` -> `{kinds:[{x402Version,scheme,network,extra?}], extensions:[], signers:{"eip155:*":[..],"solana:*":[..]}}`.
Schemes: `exact` (EVM, SVM, Aptos, Algorand, Stellar, Sui, Hedera, TON, XRPL, NEAR, Starknet, Cardano...), `upto` (EVM, SVM), `batch-settlement`, `auth-capture`.

CAIP-2: Base `eip155:8453`, Base Sepolia `eip155:84532`, Avalanche `eip155:43114`, Fuji `eip155:43113`, Ethereum `eip155:1`, Sepolia `eip155:11155111`, Polygon `eip155:137`, Amoy `eip155:80002`, Arbitrum `eip155:42161`, Arb Sepolia `eip155:421614`, OP `eip155:10`, OP Sepolia `eip155:11155420`. Solana mainnet `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`, devnet `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1`, testnet `solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z` (first 32 chars of genesis hash). v1->v2 Solana map in `mechanisms/svm/src/constants.ts` `V1_TO_V2_NETWORK_MAP`.

### exact / EVM payloads
- eip3009: `payload: {signature: "0x"+65B, authorization: {from, to, value, validAfter, validBefore, nonce: "0x"+32B}}`, decimal strings. Reference client: `validAfter = now-600`, `validBefore = now+maxTimeoutSeconds`.
- permit2: `payload: {signature, permit2Authorization: {from, permitted:{token,amount}, spender, nonce (uint256 dec), deadline, witness:{to, validAfter}}}`. Permit2 `0x000000000022D473030F116dDEE9F6B43aC78BA3`; spender must be x402ExactPermit2Proxy `0x402085c248EeA27D92E8b30b2C58ed07f9E20001` (upto proxy `0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002`, witness `(to, facilitator, validAfter)`). Domain `{name:"Permit2", chainId, verifyingContract: Permit2}`, primaryType `PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)`, `TokenPermissions(address token,uint256 amount)`, `Witness(address to,uint256 validAfter)`. Extensions `eip2612GasSponsoring`, `erc20ApprovalGasSponsoring`.
- erc7710 (spec only): `payload: {delegationManager, permissionContext, delegator}`.

### exact / SVM payload
`payload: {transaction: "<base64 serialized partially-signed versioned tx>"}`, fee-payer (`extra.feePayer`) signature missing; facilitator co-signs. Contains ComputeBudget limit+price ixs, `TransferChecked` (SPL Token or Token-2022), optional Memo, optional Lighthouse ixs (Phantom/Solflare). CU price cap 5,000,000 microlamports. SettleResponse.transaction = base58 sig.

### EIP-3009
`TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)`; `ReceiveWithAuthorization` same fields (payee must be msg.sender; not used by x402). Domain `{name, version, chainId, verifyingContract: token}`.

USDC, verified on-chain 2026-10-04 (name / version / decimals, domain separator recomputed):

| chain | CAIP-2 | address | name | ver |
|---|---|---|---|---|
| Ethereum | eip155:1 | 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 | USD Coin | 2 |
| Sepolia | eip155:11155111 | 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 | USDC | 2 |
| Base | eip155:8453 | 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 | USD Coin | 2 |
| Base Sepolia | eip155:84532 | 0x036CbD53842c5426634e7929541eC2318f3dCF7e | USDC | 2 |
| Avalanche | eip155:43114 | 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E | USD Coin | 2 |
| Fuji | eip155:43113 | 0x5425890298aed601595a70AB815c96711a31Bc65 | USD Coin | 2 |
| Polygon | eip155:137 | 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359 | USD Coin | 2 |
| Amoy | eip155:80002 | 0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582 | USDC | 2 |
| Arbitrum | eip155:42161 | 0xaf88d065e77c8cC2239327C5EDb3A432268e5831 | USD Coin | 2 |
| Arb Sepolia | eip155:421614 | 0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d | USD Coin | 2 |
| OP | eip155:10 | 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85 | USD Coin | 2 |
| OP Sepolia | eip155:11155420 | 0x5fd84259d66Cd46123540766Be93DFE6D43130D7 | USDC | 2 |

All 6 decimals. Solana USDC mints: mainnet `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, devnet `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU` (classic Token program, 6 dec). x402 default assets (`mechanisms/evm/src/defaultAssets.ts`) include non-USDC (MegaUSD 18 dec permit2, USDT0, Mezo USD): never assume 6 decimals or EIP-3009.

## AP2: two incompatible generations
**v0.2.0 (2026-04-28, current)**: mandates are **SD-JWT** (RFC 9901); delegation chains per draft-gco-oauth-delegate-sd-jwt-00 joined by **`~~`**; mandate object inside selectively-disclosed **`delegate_payload`** array claim. Root `typ: example+sd-jwt`, ES256. Intermediate hops `typ=kb+sd-jwt+kb` with `cnf`; terminal `typ=kb+sd-jwt` with `aud, nonce, sd_hash, iat`. `sd_hash` = sha256 of previous token INCLUDING trailing `~`. Schemas: `code/sdk/schemas/ap2/*.json`.
- `mandate.checkout.1` (closed CheckoutMandate): `vct, checkout_jwt` (merchant-signed UCP Checkout JWT), `checkout_hash`, `iat?, exp?`.
- `mandate.payment.1` (closed PaymentMandate): `vct, transaction_id (=checkout_hash), payee{id,name,website?}, pisp?{legal_name,brand_name,domain_name}, payment_amount{amount:int minor units, currency}, payment_instrument{id,type,description?}, execution_date?, risk_data?, iat?, exp?`.
- `mandate.checkout.open.1`: `vct, cnf, constraints[]` from `checkout.allowed_merchants{allowed[]}`, `checkout.line_items{items:[{id, acceptable_items:[{id,title}], quantity}]}` (line_items required).
- `mandate.payment.open.1`: `vct, cnf, constraints[]` (must include `payment.reference{conditional_transaction_id}`), optional payee/payment_amount/etc. Constraints: `payment.amount_range{currency,max,min?}`, `payment.allowed_payees{allowed[]}`, `payment.allowed_payment_instruments`, `payment.allowed_pisps`, `payment.budget{max,currency}`, `payment.agent_recurrence{frequency: ON_DEMAND|DAILY|WEEKLY|BIWEEKLY|MONTHLY|QUARTERLY|ANNUALLY, max_occurrences?}`, `payment.execution_date{not_before?,not_after?}`.
- Receipts: CheckoutReceipt `{status: Success|Error, iss, iat, reference, order_id | error+error_description}`; PaymentReceipt adds `payment_id, psp_confirmation_id, network_confirmation_id`.

**v0.1 legacy (pydantic `code/sdk/python/ap2/models/mandate.py`)**: `IntentMandate{user_cart_confirmation_required, natural_language_description, merchants?, skus?, requires_refundability?, intent_expiry}`; `CartMandate{contents:{id, user_cart_confirmation_required, payment_request, cart_expiry, merchant_name}, merchant_authorization?}` (b64url JWT with `cart_hash`); `PaymentMandate{payment_mandate_contents:{payment_mandate_id, payment_details_id, payment_details_total: PaymentItem, payment_response, merchant_agent, timestamp}, user_authorization?}`. W3C PaymentRequest snake_case: `{method_data:[{supported_methods,data}], details:{id, display_items[], shipping_options?, modifiers?, total}, options?, shipping_address?}`, `PaymentItem{label, amount:{currency, value: float}, pending?, refund_period=30}`. A2A DataPart keys `ap2.mandates.IntentMandate|CartMandate|PaymentMandate`. The v0.1 doc JSON examples DON'T match the models; trust the models.

**AP2 x x402**: no formal AP2 x402 extension yet. a2a-x402 v0.2 "Embedded Flow": x402 PaymentRequired inside CartMandate `payment_request.method_data[]` with `supported_methods: "https://www.x402.org/"`; x402 PaymentPayload inside PaymentMandate. AP2 v0.2 sample `x402_credentials_provider_mcp` sets **EIP-3009 nonce = keccak256(mandate-chain string)** (decoder check: bind payment to mandate) and returns `{payment_mandate_chain, payment_nonce, eip_3009_payload:{signature, authorization}}`. **That sample signs Base Sepolia USDC with domain name "USD Coin"; on-chain it's "USDC", so its signatures won't verify.** Perfect "domain mismatch" flag case.

## Other formats
- **MPP** (Stripe/Tempo, IETF draft-httpauth-payment-01, `tempoxyz/mpp-specs`): 402 `WWW-Authenticate: Payment id=..., realm=..., method=..., intent=charge|subscription, request="<b64url JCS JSON>"` (+ expires, opaque, digest, header, description). Credential `Authorization: Payment <b64url-nopad JSON {challenge, source?, payload}>`. Receipt `Payment-Receipt`. Methods: usdc, card, lightning, stellar, nearintents.
- **ACP** (OpenAI/Stripe, spec 2026-04-17): Delegate Payment request `{payment_method, allowance{reason:"one_time", max_amount (minor), currency (lowercase), checkout_session_id, merchant_id, expires_at}, risk_signals[], metadata}`, response `{id:"vt_...", created, metadata}`; checkout `payment_data{handler_id, instrument{type:"card", credential{type:"spt", token:"spt_..."}}}`.
- **Visa TAP**: RFC 9421 `Signature-Input: sig2=("@authority" "@path"); created; expires; keyId; alg="ed25519"|"rsa-pss-sha256"; nonce; tag="agent-browser-auth"|"agent-payer-auth"` + `Signature: sig2=:<b64>:`.
- x402 extensions worth recognizing: `sign-in-with-x`, `payment_identifier`, `bazaar`, `offer-and-receipt`, `builder_code`, `extension-auth-hints`.

## Fixture notes
- x402 v2 PAYMENT-SIGNATURE fixture signature is genuine: recovers to `from` 0x857b06519E91e3A54538791bDbb0E22373e36b66 with domain `{name:"USDC", version:"2", chainId:84532, verifyingContract: Base Sepolia USDC}`. With "USD Coin" it recovers to a different address: positive AND negative test.
- AP2 v0.2 open PaymentMandate ~~ closed PaymentMandate fixture verifies cryptographically (closed hop ES256 verifies with open mandate's `cnf.jwk`; $200 cap, payee merchant_1, $199 card payment). More tokens in `ap2/docs/ap2/checkout_mandate.md`.
- No real SVM exact tx exists in the repo: generate one with @solana/web3.js in tests.
