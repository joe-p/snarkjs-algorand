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
