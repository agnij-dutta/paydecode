// Type surface of the workspace library, for the web typecheck only.
// Vite resolves the runtime from packages/paydecode/src (see vite.config.ts); tsc reads
// this shim so the web's stricter lint flags are not applied to library sources.
import type { Decoded, DecodeOptions, Unrecognized } from "../../../packages/paydecode/src/types.ts";

export type { Decoded, DecodeOptions, Field, Flag, FlagLevel, Section, Unrecognized } from "../../../packages/paydecode/src/types.ts";

export declare function decode(input: string, opts?: DecodeOptions): Decoded | Unrecognized;

export interface Domain {
  name?: string;
  version?: string;
  chainId?: number | bigint;
  verifyingContract?: string;
  salt?: string;
}
export declare function typedDataHash(
  domain: Domain,
  types: Record<string, { name: string; type: string }[]>,
  primaryType: string,
  message: Record<string, unknown>,
): Uint8Array;
export declare function checksumAddress(addr: string): string;
