// paydecode: jwt.io for agent payments.
export { decode, detect } from "./detect/index.js";
export type { Detection } from "./detect/index.js";
export type { Decoded, Section, Field, Flag, FlagLevel, DecodeOptions, Unrecognized } from "./types.js";

// Lower-level building blocks, for callers that already know what they have.
export { parseTransaction, associatedTokenAddress } from "./svm/parser.js";
export { parseChain, parseSdToken, verifyEs256, sdHash } from "./crypto/sdjwt.js";
export { typedDataHash, recoverAddress, checksumAddress } from "./crypto/eip712.js";
export { networkInfo, EVM_TOKENS, SPL_TOKENS } from "./core/networks.js";
