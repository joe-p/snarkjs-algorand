# snarkjs-algorand

This repo contains an Algorand TypeScript implementation of a BLS12-381 Plonk ZKP verifier. [The contract](./contracts/verifier.algo.ts) is based on the [snarkjs verifier implementation](https://github.com/iden3/snarkjs/blob/e0c7219bd69db07845560162af7e6876d15390e1/src/plonk_verify.js?plain=1#L29).

This repo not only contains the smart contract, but also a TypeScript SDK that uses [algokit-utils](https://github.com/algorandfoundation/algokit-utils). This SDK has not yet been documented, but you can see usage in the [tests](./__test__/verifier.test.ts).

## TODO

In no particular order:

- Add input validation to the contract
- Documentation

## Why Not AlgoPlonk?

The main reason is because AlgoPlonk uses gnark for circuit compilation and proof generation. The problem with gnark is that it [does not support WASM](https://github.com/Consensys/gnark/issues/74), thus one cannot simply generate a proof client-side in the browser. Additionally, because snarkjs is written in TypeScript, we can leverage algokit-utils for a much better developer experience.
