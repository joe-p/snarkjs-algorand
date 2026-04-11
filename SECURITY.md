# Security

The code in this repo has not been audited. The primary maintainer, @joe-p, is not a professional cryptographer. Most of the client and contract code, however, is a translation of the [snarkjs](https://github.com/iden3/snarkjs) library and uses a testing strategy to ensure alignment with the original implementation. The only deviations from direct translations within the on-chain verification code are the usage of multi-scalar multiplications to significantly reduce opcode usage.

## AI Disclosure

Unless stated as an exception below, the code in this repo was written by a human with minimal AI generation. "Minimal AI generation" means that AI may have been used for some tests, comments, minor refactoring, and next edit suggestion.

### Exceptions

| File                 | Functions                                                   | Security Impact                                                                                                                                                                                                                                                                              |
| -------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| src/gnark_groth16.ts | `decodeGnarkGroth16Bn254Proof`, `decodeGnarkGroth16Bn254Vk` | These functions translate gnark proofs to snarkjs format on the client side. This is primarily for use with Succinct SP1. A bug in these functions does NOT affect the integrity of the on-chain verification. A bug in these functions, however, may lead to incorrect verification results |
