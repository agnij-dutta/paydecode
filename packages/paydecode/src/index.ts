// paydecode: jwt.io for agent payments.
export { decode, detect, MAX_INPUT_LENGTH } from "./detect/index.js";
export type { Detection } from "./detect/index.js";
export type { Decoded, Section, Field, Flag, FlagLevel, DecodeOptions, Unrecognized } from "./types.js";

// Lower-level building blocks, for callers that already know what they have.
export { parseTransaction, associatedTokenAddress } from "./svm/parser.js";
export type { ParsedTx, ParsedInstruction } from "./svm/parser.js";
export { parseChain, parseSdToken, verifyEs256, sdHash } from "./crypto/sdjwt.js";
export type { SdToken, Jwt, Disclosure } from "./crypto/sdjwt.js";
export { typedDataHash, recoverAddress, checksumAddress } from "./crypto/eip712.js";
export type { Domain, TypeMap, TypedField } from "./crypto/eip712.js";
export { networkInfo, EVM_TOKENS, SPL_TOKENS } from "./core/networks.js";
export type { NetworkInfo, EvmToken, SplToken } from "./core/networks.js";
