# snarkjs-algorand

This repo contains an Algorand TypeScript implementation of a BLS12-381 Plonk ZKP verifier. [The contract](./contracts/verifier.algo.ts) is based on the [snarkjs verifier implementation](https://github.com/iden3/snarkjs/blob/e0c7219bd69db07845560162af7e6876d15390e1/src/plonk_verify.js?plain=1#L29).

Eventually this repo aims to provide functionality similar to [AlgoPlonk](github.com/giuliop/AlgoPlonk/) by providing an SDK for building with plonk circuits on Algorand, but it currently serves as a proof of concept. The verifier is [tested](./__test__/verifier.test.ts) and works, but the off-chain code is a bit messy and not well documented (and only exists in the tests). Below is a TODO list of things I want to do in the future.

## TODO

In no particular order:

- Switch from reading files (from snarkjs CLI) to using snarkjs pragmatically
- Add input validation to the contract
- Use more TemplateVars where they make sense (i.e get rid of the hard-coded `Frw11`)
- Add more tests
- Create an SDK
- Refactor contract code to be more like a library
- PR contract generation to snarkjs?

## Why Not AlgoPlonk?

The main reason is because AlgoPlonk uses gnark for circuit compilation and proof generation. The problem with gnark is that it [does not support WASM](https://github.com/Consensys/gnark/issues/74), thus one cannot simply generate a proof client-side in the browser. Additionally, because snarkjs is written in TypeScript, we can leverage algokit-utils for a much better developer experience.
