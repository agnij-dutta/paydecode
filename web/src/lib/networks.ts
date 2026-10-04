export interface NetworkInfo {
  name: string;
  explorer: string;
  /** Query suffix appended to explorer links, e.g. "?cluster=devnet". */
  suffix?: string;
  family: "evm" | "solana";
}

const EVM: Record<string, NetworkInfo> = {
  "1": { name: "Ethereum", explorer: "https://etherscan.io", family: "evm" },
  "11155111": { name: "Sepolia", explorer: "https://sepolia.etherscan.io", family: "evm" },
  "8453": { name: "Base", explorer: "https://basescan.org", family: "evm" },
  "84532": { name: "Base Sepolia", explorer: "https://sepolia.basescan.org", family: "evm" },
  "43114": { name: "Avalanche", explorer: "https://snowtrace.io", family: "evm" },
  "43113": { name: "Avalanche Fuji", explorer: "https://testnet.snowtrace.io", family: "evm" },
  "137": { name: "Polygon", explorer: "https://polygonscan.com", family: "evm" },
  "80002": { name: "Polygon Amoy", explorer: "https://amoy.polygonscan.com", family: "evm" },
  "42161": { name: "Arbitrum", explorer: "https://arbiscan.io", family: "evm" },
  "421614": { name: "Arbitrum Sepolia", explorer: "https://sepolia.arbiscan.io", family: "evm" },
  "10": { name: "OP Mainnet", explorer: "https://optimistic.etherscan.io", family: "evm" },
  "11155420": { name: "OP Sepolia", explorer: "https://sepolia-optimism.etherscan.io", family: "evm" },
};

const V1_NAMES: Record<string, string> = {
  ethereum: "1",
  sepolia: "11155111",
  base: "8453",
  "base-sepolia": "84532",
  avalanche: "43114",
  "avalanche-fuji": "43113",
  polygon: "137",
  "polygon-amoy": "80002",
  arbitrum: "42161",
  "arbitrum-sepolia": "421614",
  optimism: "10",
};

const SOL_MAIN: NetworkInfo = { name: "Solana", explorer: "https://explorer.solana.com", family: "solana" };
const SOL_DEV: NetworkInfo = { name: "Solana devnet", explorer: "https://explorer.solana.com", suffix: "?cluster=devnet", family: "solana" };
const SOL_TEST: NetworkInfo = { name: "Solana testnet", explorer: "https://explorer.solana.com", suffix: "?cluster=testnet", family: "solana" };

/** Resolve a CAIP-2 id or x402 v1 network name to explorer info. */
export function resolveNetwork(id: string | undefined | null): NetworkInfo | null {
  if (!id) return null;
  const s = id.trim();
  const caip = s.match(/eip155:(\d+)/);
  if (caip) return EVM[caip[1]] ?? null;
  if (/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/.test(s) || s === "solana") return SOL_MAIN;
  if (/solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1/.test(s) || s === "solana-devnet") return SOL_DEV;
  if (/solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z/.test(s) || s === "solana-testnet") return SOL_TEST;
  const lower = s.toLowerCase();
  if (V1_NAMES[lower]) return EVM[V1_NAMES[lower]];
  return null;
}

/** Find the first network-looking value inside a structure (fields first, then raw JSON). */
export function findNetwork(fieldValues: string[], raw: unknown): NetworkInfo | null {
  for (const v of fieldValues) {
    const n = resolveNetwork(v.match(/(eip155:\d+|solana:[1-9A-HJ-NP-Za-km-z]{32})/)?.[1]);
    if (n) return n;
  }
  const seen = new Set<unknown>();
  const walk = (node: unknown, depth: number): NetworkInfo | null => {
    if (depth > 6 || node === null || typeof node !== "object" || seen.has(node)) return null;
    seen.add(node);
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (k === "network" && typeof v === "string") {
        const n = resolveNetwork(v);
        if (n) return n;
      }
      const r = walk(v, depth + 1);
      if (r) return r;
    }
    return null;
  };
  return walk(raw, 0);
}

export const isEvmAddress = (s: string) => /^0x[0-9a-fA-F]{40}$/.test(s);
export const isEvmTxHash = (s: string) => /^0x[0-9a-fA-F]{64}$/.test(s);
export const isBase58 = (s: string, min = 32, max = 44) =>
  new RegExp(`^[1-9A-HJ-NP-Za-km-z]{${min},${max}}$`).test(s);

export function explorerLink(net: NetworkInfo | null, value: string, type: "address" | "tx"): string | null {
  if (!net) return null;
  if (net.family === "evm") {
    if (type === "address" && !isEvmAddress(value)) return null;
    if (type === "tx" && !isEvmTxHash(value)) return null;
  } else {
    if (type === "address" && !isBase58(value)) return null;
    if (type === "tx" && !isBase58(value, 64, 90)) return null;
  }
  return `${net.explorer}/${type}/${value}${net.suffix ?? ""}`;
}
