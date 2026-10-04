// Regenerates the synthetic fixtures in test/fixtures/ (deterministic).
// Run: npx tsx scripts/gen-fixtures.mts
import { writeFileSync, readFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";
import { keccak256, toHex } from "viem";

const here = new URL("../test/fixtures/", import.meta.url);
const fx = JSON.parse(readFileSync(new URL("fixtures.json", here), "utf8"));

// AP2 v0.2 sample `x402_credentials_provider_mcp` bundle, reproduced with the
// sample's own defaults (Anvil account 0 as the user, Anvil account 1 as the
// merchant, Base Sepolia USDC) and its EIP-712 domain name "USD Coin".
// Publicly known Anvil/Hardhat development key, the AP2 sample's default user. Never holds real funds.
const ANVIL_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const MERCHANT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
export async function ap2Bundle(domainName: string) {
  const chain: string = fx.ap2_v02_open_plus_closed_payment_mandate_chain;
  const account = privateKeyToAccount(ANVIL_0);
  const nonce = keccak256(toHex(chain));
  const message = {
    from: account.address,
    to: MERCHANT,
    value: 19900n * 10000n,
    validAfter: 0n,
    validBefore: 1777342370n + 3600n,
    nonce,
  } as const;
  const signature = await account.signTypedData({
    domain: { name: domainName, version: "2", chainId: 84532, verifyingContract: USDC_BASE_SEPOLIA },
    types: {
      TransferWithAuthorization: [
        { name: "from", type: "address" },
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" },
        { name: "validBefore", type: "uint256" },
        { name: "nonce", type: "bytes32" },
      ],
    },
    primaryType: "TransferWithAuthorization",
    message,
  });
  // web3.py HexBytes.hex() drops the 0x prefix; mirror the sample's output.
  return {
    payment_mandate_chain: chain,
    payment_nonce: "a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3",
    eip_3009_payload: {
      signature: signature.slice(2),
      authorization: {
        from: account.address,
        to: MERCHANT,
        value: String(message.value),
        validAfter: "0",
        validBefore: String(message.validBefore),
        nonce: nonce.slice(2),
      },
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  writeFileSync(new URL("ap2-x402-bundle.json", here), JSON.stringify(await ap2Bundle("USD Coin"), null, 2) + "\n");
  console.log("wrote ap2-x402-bundle.json");
}
