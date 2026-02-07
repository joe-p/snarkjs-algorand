import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import * as snarkjs from "snarkjs";
import {
  getGroth16Bn254Proof,
  Groth16Bn254AppVerifier,
  Groth16Bn254LsigVerifier,
  type Groth16Bn254VerificationKey,
} from "../src/groth16";
import {
  Groth16Bn254SignalsAndProofClient,
  Groth16Bn254SignalsAndProofFactory,
} from "../contracts/clients/Groth16Bn254SignalsAndProof";
import type { Groth16Bn254Proof } from "../src/groth16";
import {
  decodeGnarkBn254Proof,
  decodeGnarkBn254Vk,
} from "../src/gnark_groth16";

const LSIG_BUDGET = 20_000; // Budget for each logicsig
const APP_BUDGET = 700; // Budget for the app call
const GROUP_TXN_SIZE = 16;
const EXTRA_OPCODE_BUDGET = LSIG_BUDGET * GROUP_TXN_SIZE - APP_BUDGET; // Max budget possible with a group of 16 lsigs
const algorand = AlgorandClient.defaultLocalNet();

describe("groth16 bn254 verifier", () => {
  let debugVerifier: Groth16Bn254AppVerifier;
  let verifier: Groth16Bn254AppVerifier;
  let curve: any;

  beforeAll(async () => {
    const defaultSender = await algorand.account.localNetDispenser();

    // @ts-expect-error curves is not typed
    curve = await snarkjs.curves.getCurveFromName("bn128");
    debugVerifier = new Groth16Bn254AppVerifier({
      algorand,
      zKey: "circuit/groth16_bn254_circuit_final.zkey",
      wasmProver: "circuit/circuit_bn254_js/circuit_bn254.wasm",
    });
    await debugVerifier.deploy({
      appName: `groth16-bn254-verifier-${Date.now()}`,
      debugLogging: true,
      defaultSender,
    });

    verifier = new Groth16Bn254AppVerifier({
      algorand,
      zKey: "circuit/groth16_bn254_circuit_final.zkey",
      wasmProver: "circuit/circuit_bn254_js/circuit_bn254.wasm",
    });

    await verifier.deploy({
      appName: `groth16-bn254-verifier-${Date.now()}`,
      defaultSender,
    });
  });

  afterAll(async () => {
    await curve.terminate();
  });

  it("fails with wrong signal", async () => {
    const proof = await getGroth16Bn254Proof(
      "circuit/groth16_bn254_proof.json",
      curve,
    );
    const signals = [1337n];

    const simResult = debugVerifier.simulateVerificationWithProofAndSignals(
      { signals, proof },
      {
        extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
        allowMoreLogging: true,
      },
    );

    await expect(simResult).rejects.toThrow();
  });

  it("works", async () => {
    const proof = await getGroth16Bn254Proof(
      "circuit/groth16_bn254_proof.json",
      curve,
    );
    // Read the public signal from the generated public_bn254.json
    // For the same input {a: 3, b: 11}, the output will be different due to different field
    const signals = [
      7713112592372404476342535432037683616424591277138491596200192981572885523208n,
    ];

    // We are testing using an app so we can log, so we need to increase the opcode budget
    const simResult = await verifier.simulateVerificationWithProofAndSignals(
      { signals, proof },
      {
        extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
        allowMoreLogging: true,
      },
    );

    simResult.simulateResponse.txnGroups[0]?.appBudgetConsumed;

    const budgetUsed =
      simResult.simulateResponse.txnGroups[0]!.appBudgetConsumed!;

    expect(budgetUsed).toMatchSnapshot("budget used");
    expect(Math.ceil(budgetUsed / LSIG_BUDGET)).toMatchSnapshot(
      "number of lsig txns required for budget",
    );
    expect(Math.ceil(budgetUsed / APP_BUDGET)).toMatchSnapshot(
      "number of app calls required for budget",
    );
  });

  it("works with fullProve", async () => {
    const simResult = await verifier.simulateVerification(
      { a: 10, b: 21 },
      {
        extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
        allowMoreLogging: true,
      },
    );

    expect(simResult.simulateResponse.txnGroups[0]?.failedAt).toBeUndefined();
  });
});

describe("groth16 bn254 verifier lsig", () => {
  let verifier: Groth16Bn254LsigVerifier;
  let algorand: AlgorandClient;
  let client: Groth16Bn254SignalsAndProofClient;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    verifier = new Groth16Bn254LsigVerifier({
      algorand,
      zKey: "circuit/groth16_bn254_circuit_final.zkey",
      wasmProver: "circuit/circuit_bn254_js/circuit_bn254.wasm",
    });

    const signalsAndProofFactory = new Groth16Bn254SignalsAndProofFactory({
      algorand,
      defaultSender: await algorand.account.localNetDispenser(),
    });

    const { appClient } = await signalsAndProofFactory.deploy({
      onUpdate: "append",
    });

    client = appClient;
  });

  it("works", async () => {
    const group = client.newGroup();

    await verifier.verificationParams({
      inputs: { a: 10, b: 21 },
      composer: group,
      paramsCallback: async (params) => {
        const { appParams, lsigsFee } = params;

        // Call app with signals and proof via lsig
        group.signalsAndProof(appParams);

        // Pay the required fees
        const feePayer = await algorand.account.localNetDispenser();
        group.addTransaction(
          await algorand.createTransaction.payment({
            sender: feePayer,
            amount: microAlgos(0),
            receiver: feePayer,
            extraFee: lsigsFee,
          }),
        );
      },
    });

    await group.send();
  });

  describe("with sp1 proof", () => {
    const sp1ProofHex =
      "0711d4dc2d659f0b2448452f8335e21871fbf11bc48a46703e138a43129e0b1a18ea44d7b7dd91ce2c7c81f0a735a1dc1918bac8b2bed97ce3e6ccb870c118012ce5d57f809a6ef9bb4c5cfbeede2742de2e65e8a79498a890e516322603cfd523e2fe0c519f39cf61100c87952f7497441682ebd883db2add4821c681c6da9b1d1d5f22c5ac6d8843646781866b8ce9d39177c87df9d4cd571d775c5a80774a07ca7e429f8085809b78e83109bb2cc18cc581b72a5df3e5113effe546fc38230a920df10c1cdd0bb12666753746c29fc770119e95819cf5490190fb4b1606ad13ae86c43406a49a81d7b969bbbb7797435aa2ba1d00fcbf54bbec2325154f2b";

    const sp1VkHex =
      "ad4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e2e1a1575c2e494d3613e95e43b622318d9225c820e46acd08e8c987b44051195bc967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6edd8e5739a73d657e832a336791977332a4b96e5bbfdcb9903afe487db9aa6cb5ddcc7cb8de715675f21f01ecc9b46d236e0865e0cc020024521998269845f74e603ff41f4ba0c37fe2caf27354d28e4b8f83d3b76777a63b327d736bffb0122ed00000003a6091e1cafb0ad8a4ea0a694cd3743ebf524779233db734c451d28b58aa9758e861c3fd0fd3da25d2607c227d090cca750ed36c6ec878755e537c1c48951fb4c84eab241388a79817fe0e0e2ead0b2ec4ffdec51a16028dee020634fd129e71c0000000000000000";

    const signals = [
      286806484355116472985898119495067009235898359779904212419052995325315545470n,
      1238059838539250559833414393824527044623638835038285939466258117562326526889n,
    ];

    function hexToBytes(hex: string): Uint8Array {
      const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
      const bytes = new Uint8Array(clean.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
      }
      return bytes;
    }

    const proof = decodeGnarkBn254Proof(hexToBytes(sp1ProofHex));

    const vk = decodeGnarkBn254Vk(hexToBytes(sp1VkHex));

    it("rejects oversized num_k", () => {
      const vkBytes = hexToBytes(sp1VkHex);
      const mutated = new Uint8Array(vkBytes);
      mutated[288] = 0x00;
      mutated[289] = 0x01;
      mutated[290] = 0x00;
      mutated[291] = 0x00;
      expect(() => decodeGnarkBn254Vk(mutated)).toThrow(
        "num_k must be <= 1024",
      );
    });

    it("works with app verifier", async () => {
      const sp1App = new Groth16Bn254AppVerifier({
        algorand,
        vk,
      });

      await sp1App.deploy({
        appName: `groth16-bn254-verifier-sp1-${Date.now()}`,
        defaultSender: await algorand.account.localNetDispenser(),
        debugLogging: true,
      });

      await sp1App.simulateVerificationWithProofAndSignals(
        {
          signals,
          proof,
        },
        {
          extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
          allowMoreLogging: true,
        },
      );
    });

    it("rejects invalid compressed G1 flag", () => {
      const proofBytes = hexToBytes(sp1ProofHex);
      proofBytes[0] = 0x00;
      expect(() => decodeGnarkBn254Proof(proofBytes)).toThrow(
        "Invalid G1 point flag",
      );
    });

    it("works with lsig verifier", async () => {
      const sp1Lsig = new Groth16Bn254LsigVerifier({
        algorand,
        vk,
      });

      const group = client.newGroup();

      await sp1Lsig.verificationParams({
        proof,
        signals,
        composer: group,
        paramsCallback: async (params) => {
          const { appParams, lsigsFee } = params;

          // Call app with signals and proof via lsig
          group.signalsAndProof(appParams);

          // Pay the required fees
          const feePayer = await algorand.account.localNetDispenser();
          group.addTransaction(
            await algorand.createTransaction.payment({
              sender: feePayer,
              amount: microAlgos(0),
              receiver: feePayer,
              extraFee: lsigsFee,
            }),
          );
        },
      });

      await group.send();
    });
  });
});
