# snarkjs-algorand

This repo contains Algorand TypeScript implementations of BLS12-381 ZKP verifiers for both PLONK and Groth16 proof systems. The contracts are based on the [snarkjs verifier implementations](https://github.com/iden3/snarkjs).

This repo not only contains the smart contracts, but also TypeScript SDKs that use [algokit-utils](https://github.com/algorandfoundation/algokit-utils). You can see usage examples in the tests:
- [PLONK tests](./__test__/plonk_verifier.test.ts)
- [Groth16 tests](./__test__/groth16_verifier.test.ts)

## TODO

In no particular order:

- Add input validation to the contract
- Documentation

## Why Not AlgoPlonk?

The main reason is because AlgoPlonk uses gnark for circuit compilation and proof generation. The problem with gnark is that it [does not support WASM](https://github.com/Consensys/gnark/issues/74), thus one cannot simply generate a proof client-side in the browser. Additionally, because snarkjs is written in TypeScript, we can leverage algokit-utils for a much better developer experience.
