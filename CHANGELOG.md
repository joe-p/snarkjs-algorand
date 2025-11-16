# 0.8.0

## SECURITY

- PLONK: Lagrange evaluations are now done on chain to prevent potential vulnerabilities from an untrusted prover.

## BREAKING CHANGES

- Many of the method and class names have changed to accommodate differentiation between PLONK and Groth16.
- All previously existing functions are now imported from the `/plonk` module rather than the root module.

## Features

- Preliminary support for Groth16 verifiers on Algorand
