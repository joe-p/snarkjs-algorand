# 0.11.0

## BREAKING CHANGES

- Lsig verifiers now require `appOffset` parameter to specify the offset from lsig group index to app call
  - To preserve previous behavior, use `appOffset: 0`
- Lsig verifiers now require `totalLsigs` parameter
  - To preserve previous behavior, use `totalLsigs: 6`
- `paramsCallback` API changed: `appParams` renamed to `lsigParams`, `args` moved to separate property
  - Old: `paramsCallback: ({ appParams: { sender, staticFee, args }, lsigsFee })`
  - New: `paramsCallback: ({ lsigParams: { sender, staticFee }, args, lsigsFee })`

## Features

- Lsig contracts now use `GTxn.applicationArgs` with configurable `APP_OFFSET` template variable for more flexible transaction group layouts

# 0.10.0

## BREAKING CHANGES

- All verifier class constructors now accept an options object instead of positional parameters
  - `Groth16Bls12381AppVerifier`, `Groth16Bls12381LsigVerifier`, `Groth16Bn254AppVerifier`, `Groth16Bn254LsigVerifier`, `PlonkAppVerifier`, `PlonkLsigVerifier`
  - New signature: `{ algorand, zKey, wasmProver }` or `{ algorand, vk }`

## Features

- Added support for passing verification keys (VK) directly to verifiers without requiring zKey and wasmProver files
- Added `gnark_groth16` module with `decodeGnarkGroth16Bn254Proof` and `decodeGnarkGroth16Bn254Vk` functions for SP1 proof verification support

# 0.9.0

## BREAKING CHANGES

- `VerificationKey` and `Proof` for Groth16 have been renamed to `GrothVerificationKey` and `GrothProof` respectively to avoid confusion with PLONK types.
- `Groth16SignalsAndProof` renamed to `Groth16Bls12381SignalsAndProof` to differentiate between BLS12-381 and BN254 curves.
- `Groth16Witness` renamed to `Groth16Bls12381Witness` to differentiate between BLS12-381 and BN254 curves.
- `Groth16AppVerifier` renamed to `Groth16Bls12381AppVerifier` to differentiate between BLS12-381 and BN254 curves.

## Features

- Added `Groth16LsigVerifier` for verifying Groth16 proofs in an lsig
- Added support for BN254 curve in Groth16 verifiers

# 0.8.0

## SECURITY

- PLONK: Lagrange evaluations are now done on chain to prevent potential vulnerabilities from an untrusted prover.

## BREAKING CHANGES

- Many of the method and class names have changed to accommodate differentiation between PLONK and Groth16.

## Features

- Preliminary support for Groth16 verifiers on Algorand
