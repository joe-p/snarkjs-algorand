# UNRELEASED: 0.9.0

## BREAKING CHANGES

- `VerificationKey` and `Proof` for Groth16 have been renamed to `GrothVerificationKey` and `GrothProof` respectively to avoid confusion with PLONK types.

## Features

- Added `Groth16LsigVerifier` for verifying Groth16 proofs in an lsig

# 0.8.0

## SECURITY

- PLONK: Lagrange evaluations are now done on chain to prevent potential vulnerabilities from an untrusted prover.

## BREAKING CHANGES

- Many of the method and class names have changed to accommodate differentiation between PLONK and Groth16.

## Features

- Preliminary support for Groth16 verifiers on Algorand
