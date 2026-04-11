# snarkjs-algorand

This repo contains Algorand TypeScript implementations of BLS12-381 ZKP verifiers for both PLONK and Groth16 proof systems. The contracts are based on the [snarkjs verifier implementations](https://github.com/iden3/snarkjs).

This repo also contains an SDK for interacting with these verifiers on the Algorand blockchain. The SDK is a work in progress and not yet stable. You can view usage examples in the tests:

- [PLONK tests](./__test__/plonk_verifier.test.ts)
- [Groth16 tests](./__test__/groth16_verifier.test.ts)

Eventually there will be proper documentation, but for now use at your own risk!

## Security

The code in this repo has not been audited. Use at your own risk! See [SECURITY.md](./SECURITY.md) for more information.

## Why Not AlgoPlonk?

The main reason is because AlgoPlonk uses gnark for circuit compilation and proof generation. The problem with gnark is that it [does not support WASM](https://github.com/Consensys/gnark/issues/74), thus one cannot simply generate a proof client-side in the browser. Additionally, because snarkjs is written in TypeScript, we can leverage algokit-utils for a much better developer experience.
