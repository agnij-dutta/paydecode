// Network + asset knowledge. Sources: docs/SPEC-NOTES.md (USDC rows verified
// on-chain 2026-10-04) and x402-foundation/x402 mechanisms/evm/src/defaultAssets.ts.

export interface NetworkInfo {
  family: "evm" | "svm" | "other";
  /** Human name, e.g. "Base Sepolia". */
  name: string;
  /** CAIP-2 id when known, e.g. "eip155:84532". */
  caip2?: string;
  chainId?: number;
  testnet?: boolean;
  /** True when we recognized the network id. */
  known: boolean;
}

interface ChainRow {
  id: number;
  name: string;
  v1?: string;
  testnet?: boolean;
}

const EVM_CHAINS: ChainRow[] = [
  { id: 1, name: "Ethereum", v1: "ethereum" },
  { id: 11155111, name: "Sepolia", v1: "sepolia", testnet: true },
  { id: 8453, name: "Base", v1: "base" },
  { id: 84532, name: "Base Sepolia", v1: "base-sepolia", testnet: true },
  { id: 43114, name: "Avalanche C-Chain", v1: "avalanche" },
  { id: 43113, name: "Avalanche Fuji", v1: "avalanche-fuji", testnet: true },
  { id: 137, name: "Polygon", v1: "polygon" },
  { id: 80002, name: "Polygon Amoy", v1: "polygon-amoy", testnet: true },
  { id: 42161, name: "Arbitrum One" },
  { id: 421614, name: "Arbitrum Sepolia", testnet: true },
  { id: 10, name: "OP Mainnet" },
  { id: 11155420, name: "OP Sepolia", testnet: true },
  { id: 2741, name: "Abstract", v1: "abstract" },
  { id: 11124, name: "Abstract Testnet", v1: "abstract-testnet", testnet: true },
  { id: 4689, name: "IoTeX", v1: "iotex" },
  { id: 1329, name: "Sei", v1: "sei" },
  { id: 1328, name: "Sei Testnet", v1: "sei-testnet", testnet: true },
  { id: 3338, name: "peaq", v1: "peaq" },
  { id: 1514, name: "Story", v1: "story" },
  { id: 41923, name: "EDU Chain", v1: "educhain" },
  { id: 324705682, name: "SKALE Base Sepolia", v1: "skale-base-sepolia", testnet: true },
  { id: 4326, name: "MegaETH", v1: "megaeth" },
  { id: 143, name: "Monad", v1: "monad" },
  { id: 10143, name: "Monad Testnet", v1: "monad-testnet", testnet: true },
  { id: 988, name: "Stable", v1: "stable" },
  { id: 2201, name: "Stable Testnet", v1: "stable-testnet", testnet: true },
  { id: 42220, name: "Celo", v1: "celo" },
  { id: 11142220, name: "Celo Sepolia", testnet: true },
  { id: 14, name: "Flare", v1: "flare" },
  { id: 31612, name: "Mezo" },
  { id: 31611, name: "Mezo Testnet", testnet: true },
  { id: 723487, name: "Radius" },
  { id: 72344, name: "Radius Testnet", testnet: true },
  { id: 36900, name: "ADI Chain" },
  { id: 190415, name: "HPP" },
  { id: 181228, name: "HPP Sepolia", testnet: true },
  { id: 50, name: "XDC Network" },
  { id: 51, name: "XDC Apothem", testnet: true },
  { id: 38833, name: "Igra" },
  { id: 5042, name: "Arc" },
  { id: 5042002, name: "Arc Testnet", testnet: true },
];

const SOLANA = [
  { caip2: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", v1: "solana", name: "Solana", testnet: false },
  { caip2: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", v1: "solana-devnet", name: "Solana Devnet", testnet: true },
  { caip2: "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z", v1: "solana-testnet", name: "Solana Testnet", testnet: true },
];

export function networkInfo(network: unknown): NetworkInfo {
  const n = typeof network === "string" ? network.trim() : String(network ?? "");
  const lower = n.toLowerCase();
  const sol = SOLANA.find((s) => s.caip2 === n || s.v1 === lower);
  if (sol) return { family: "svm", name: sol.name, caip2: sol.caip2, testnet: sol.testnet, known: true };
  if (lower.startsWith("solana")) return { family: "svm", name: `Solana (${n})`, caip2: n.includes(":") ? n : undefined, known: false };
  const m = n.match(/^eip155:(\d+)$/);
  if (m) {
    const id = Number(m[1]);
    const row = EVM_CHAINS.find((c) => c.id === id);
    return row
      ? { family: "evm", name: row.name, caip2: n, chainId: id, testnet: !!row.testnet, known: true }
      : { family: "evm", name: `EVM chain ${id}`, caip2: n, chainId: id, known: false };
  }
  const v1 = EVM_CHAINS.find((c) => c.v1 === lower);
  if (v1) return { family: "evm", name: v1.name, caip2: `eip155:${v1.id}`, chainId: v1.id, testnet: !!v1.testnet, known: true };
  return { family: "other", name: n || "unknown network", caip2: n.includes(":") ? n : undefined, known: false };
}

export function chainName(chainId: number): string {
  return EVM_CHAINS.find((c) => c.id === chainId)?.name ?? `EVM chain ${chainId}`;
}

export interface EvmToken {
  chainId: number;
  address: string;
  /** EIP-712 domain name. */
  name: string;
  /** EIP-712 domain version. */
  version: string;
  decimals: number;
  symbol: string;
  transfer: "eip3009" | "permit2";
  /** "onchain" = verified against the deployed contract; "x402-default" = from x402's default asset table. */
  source: "onchain" | "x402-default";
}

const t = (
  chainId: number,
  address: string,
  name: string,
  version: string,
  decimals: number,
  symbol: string,
  source: EvmToken["source"],
  transfer: EvmToken["transfer"] = "eip3009",
): EvmToken => ({ chainId, address, name, version, decimals, symbol, source, transfer });

export const EVM_TOKENS: EvmToken[] = [
  t(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USD Coin", "2", 6, "USDC", "onchain"),
  t(11155111, "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", "USDC", "2", 6, "USDC", "onchain"),
  t(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USD Coin", "2", 6, "USDC", "onchain"),
  t(84532, "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "USDC", "2", 6, "USDC", "onchain"),
  t(43114, "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", "USD Coin", "2", 6, "USDC", "onchain"),
  t(43113, "0x5425890298aed601595a70AB815c96711a31Bc65", "USD Coin", "2", 6, "USDC", "onchain"),
  t(137, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "USD Coin", "2", 6, "USDC", "onchain"),
  t(80002, "0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582", "USDC", "2", 6, "USDC", "onchain"),
  t(42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "USD Coin", "2", 6, "USDC", "onchain"),
  t(421614, "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d", "USD Coin", "2", 6, "USDC", "onchain"),
  t(10, "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "USD Coin", "2", 6, "USDC", "onchain"),
  t(11155420, "0x5fd84259d66Cd46123540766Be93DFE6D43130D7", "USDC", "2", 6, "USDC", "onchain"),
  t(4326, "0xFAfDdbb3FC7688494971a79cc65DCa3EF82079E7", "MegaUSD", "1", 18, "MegaUSD", "x402-default", "permit2"),
  t(143, "0x754704Bc059F8C67012fEd69BC8A327a5aafb603", "USDC", "2", 6, "USDC", "x402-default"),
  t(10143, "0x534b2f3A21130d7a60830c2Df862319e593943A3", "USDC", "2", 6, "USDC", "x402-default"),
  t(988, "0x779Ded0c9e1022225f8E0630b35a9b54bE713736", "USDT0", "1", 6, "USDT0", "x402-default"),
  t(2201, "0x78Cf24370174180738C5B8E352B6D14c83a6c9A9", "USDT0", "1", 6, "USDT0", "x402-default"),
  t(31612, "0xdD468A1DDc392dcdbEf6db6e34E89AA338F9F186", "Mezo USD", "1", 18, "mUSD", "x402-default", "permit2"),
  t(31611, "0x118917a40FAF1CD7a13dB0Ef56C86De7973Ac503", "Mezo USD", "1", 18, "mUSD", "x402-default", "permit2"),
  t(723487, "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb", "Stable Coin", "1", 6, "SBC", "x402-default", "permit2"),
  t(72344, "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb", "Stable Coin", "1", 6, "SBC", "x402-default", "permit2"),
  t(36900, "0x9cb8142aEBBcdc60AF7c97Af897A67A8f3CA71C2", "USDC.e", "2", 6, "USDC.e", "x402-default"),
  t(190415, "0x401eCb1D350407f13ba348573E5630B83638E30D", "Bridged USDC", "2", 6, "USDC.e", "x402-default"),
  t(181228, "0x401eCb1D350407f13ba348573E5630B83638E30D", "Bridged USDC", "2", 6, "USDC.e", "x402-default"),
  t(50, "0xfA2958CB79b0491CC627c1557F441eF849Ca8eb1", "USDC", "2", 6, "USDC", "x402-default"),
  t(51, "0xb5AB69F7bBada22B28e79C8FFAECe55eF1c771D4", "USDC", "2", 6, "USDC", "x402-default"),
  t(38833, "0xA5b8BF902b2844dA17d4506cc827F7F1681735E7", "USDC", "1", 6, "USDC", "x402-default", "permit2"),
  t(14, "0xe7cd86e13AC4309349F30B3435a9d337750fC82D", "USD₮0", "1", 6, "USDT0", "x402-default"),
  t(42220, "0xcebA9300f2b948710d2653dD7B07f33A8B32118C", "USDC", "2", 6, "USDC", "x402-default"),
  t(11142220, "0x01C5C0122039549AD1493B8220cABEdD739BC44E", "USDC", "2", 6, "USDC", "x402-default"),
  t(1329, "0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392", "USDC", "2", 6, "USDC", "x402-default"),
  t(1328, "0x4fCF1784B31630811181f670Aea7A7bEF803eaED", "USDC", "2", 6, "USDC", "x402-default"),
  t(5042, "0x3600000000000000000000000000000000000000", "USDC", "2", 6, "USDC", "x402-default"),
  t(5042002, "0x3600000000000000000000000000000000000000", "USDC", "2", 6, "USDC", "x402-default"),
];

/** Look up a token by chain + address. */
export function findEvmToken(chainId: number | undefined, address: unknown): EvmToken | undefined {
  if (typeof address !== "string") return undefined;
  const a = address.toLowerCase();
  return EVM_TOKENS.find((tk) => tk.address.toLowerCase() === a && (chainId === undefined || tk.chainId === chainId));
}

/** Tokens at this address on any chain (to spot "right token, wrong chain"). */
export function tokensAtAddress(address: unknown): EvmToken[] {
  if (typeof address !== "string") return [];
  const a = address.toLowerCase();
  return EVM_TOKENS.filter((tk) => tk.address.toLowerCase() === a);
}

export interface SplToken {
  mint: string;
  symbol: string;
  decimals: number;
  network: string;
}

export const SPL_TOKENS: SplToken[] = [
  { mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", symbol: "USDC", decimals: 6, network: "Solana" },
  { mint: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", symbol: "USDC", decimals: 6, network: "Solana Devnet" },
];

export const findSplToken = (mint: unknown) => SPL_TOKENS.find((s) => s.mint === mint);

export const PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
export const X402_EXACT_PERMIT2_PROXY = "0x402085c248EeA27D92E8b30b2C58ed07f9E20001";
export const X402_UPTO_PERMIT2_PROXY = "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002";
