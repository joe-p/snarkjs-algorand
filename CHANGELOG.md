# 0.15.0 (unreleased)

## BREAKING CHANGES

This release replaces `@algorandfoundation/algokit-utils` with
[AlgoKit Lite](https://github.com/joe-p/algokit-lite-ts). The SDK interfaces now
follow AlgoKit Lite's, so nearly every call site needs updating.

- `@algorandfoundation/algokit-utils` is no longer a peer dependency; `algokit-lite` is
- `algosdk` peer dependency raised to `^3.7.0`
- Verifiers take `algod` (an `Algodv2`) instead of `algorand` (an `AlgorandClient`)
- `AppVerifier` takes a `sender` at construction, which every call defaults to,
  instead of a `defaultSender` at deploy time
- `AppVerifier.deploy()` is replaced by `AppVerifier.create()`. AlgoKit Lite has no
  idempotent deployer, so creation always creates a new app and `appName` is gone
- Simulate options are now an `algosdk.modelsv2.SimulateRequest` instead of
  AlgoKit Utils' `RawSimulateOptions`. A failed simulation no longer throws;
  inspect `simulateResponse.txnGroups[0].failureMessage`
- `LsigVerificationArgs.composer` is an AlgoKit Lite `Composer`
- Generated clients are produced by AlgoKit Lite's generator: the `*Factory`
  classes are gone, `*Client` classes gain a static `create.bare`, and each
  client exports `APP_SPEC`
- Struct fields keep the names the ARC56 contract declares rather than being
  camel cased. `Groth16*Proof` fields are now `pi_a`/`pi_b`/`pi_c`, verification
  key fields are `vk_alpha_1`/`vk_beta_2`/`vk_gamma_2`/`vk_delta_2`/`IC`, and
  `PlonkProof`/`PlonkVerificationKey` fields are `A`/`B`/`C`/`Z`/`T1`/`Wxi`/
  `eval_a`/`Ql`/`X_2` and so on. This also changes what
  `decodeGnarkGroth16Bn254Proof` and `decodeGnarkGroth16Bn254Vk` return
- Byte array fields are typed `Uint8Array` (and `Uint8Array[]` for `IC`), so the
  generated clients no longer need `@ts-nocheck`

## Features

- `AppVerifier.verifyParams()` returns the params for a `verify` call so it can be
  composed into a larger transaction group

# 0.14.0

## BREAKING CHANGES

- `algosdk` and `@algorandfoundation/algokit-utils` are now peer dependencies

# 0.13.0

## Features

- Contract files are now exported under "snarkjs-algorand/contracts"

# 0.12.0

## BREAKING CHANGES

- `extraLsigsTxns` in `paramsCallback` has changed from `Transaction[]` to `TransactionWithSigner[]`

## Fixes

- Use explicit sender address and signer for lsigs in verification group

## Notes

- This release also includes some significant refactors to the verifiers. Please report any new bugs

# 0.11.0

## BREAKING CHANGES

- Lsig verifiers now require `appOffset` parameter to specify the offset from lsig group index to app call
  - To preserve previous behavior, use `appOffset: 0`
- Lsig verifiers now require `totalLsigs` parameter
  - To preserve previous behavior, use `totalLsigs: 6`
- `paramsCallback` API changed: `appParams` renamed to `lsigParams`, `args` moved to separate property
  - Old: `paramsCallback: ({ appParams: { sender, staticFee, args } })`
  - New: `paramsCallback: ({ lsigParams: { sender, staticFee }, args })`

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
