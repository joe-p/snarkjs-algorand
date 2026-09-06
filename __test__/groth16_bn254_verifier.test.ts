import { describe, it, expect, beforeAll, afterAll } from "vitest";
import algosdk from "algosdk";
import { BASE_USAGE, Localnet } from "algokit-lite";
import * as snarkjs from "snarkjs";
import {
  getGroth16Bn254Proof,
  Groth16Bn254AppVerifier,
  Groth16Bn254LsigVerifier,
} from "../src/groth16";
import { Groth16Bn254SignalsAndProofClient } from "../contracts/clients/Groth16Bn254SignalsAndProof";
import {
  decodeGnarkGroth16Bn254Proof,
  decodeGnarkGroth16Bn254Vk,
} from "../src/gnark_groth16";

const LSIG_BUDGET = 20_000; // Budget for each logicsig
const APP_BUDGET = 700; // Budget for the app call
const GROUP_TXN_SIZE = 16;
const EXTRA_OPCODE_BUDGET = LSIG_BUDGET * GROUP_TXN_SIZE - APP_BUDGET; // Max budget possible with a group of 16 lsigs
const localnet = new Localnet();

function maxBudgetSimulateRequest() {
  return new algosdk.modelsv2.SimulateRequest({
    txnGroups: [],
    extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
    allowMoreLogging: true,
  });
}

function groupResult(
  simulateResponse: algosdk.modelsv2.SimulateResponse,
): algosdk.modelsv2.SimulateTransactionGroupResult {
  const group = simulateResponse.txnGroups[0];
  if (!group) throw new Error("Expected a simulated transaction group");
  return group;
}

describe("groth16 bn254 verifier", () => {
  let debugVerifier: Groth16Bn254AppVerifier;
  let verifier: Groth16Bn254AppVerifier;
  let curve: any;

  beforeAll(async () => {
    const sender = await localnet.dispenser();

    // @ts-expect-error curves is not typed
    curve = await snarkjs.curves.getCurveFromName("bn128");
    debugVerifier = new Groth16Bn254AppVerifier({
      algod: localnet.algod,
      sender,
      zKey: "circuit/groth16_bn254_circuit_final.zkey",
      wasmProver: "circuit/circuit_bn254_js/circuit_bn254.wasm",
    });
    await debugVerifier.create({ debugLogging: true });

    verifier = new Groth16Bn254AppVerifier({
      algod: localnet.algod,
      sender,
      zKey: "circuit/groth16_bn254_circuit_final.zkey",
      wasmProver: "circuit/circuit_bn254_js/circuit_bn254.wasm",
    });
    await verifier.create();
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

    const { simulateResponse } =
      await debugVerifier.simulateVerificationWithProofAndSignals(
        { signals, proof },
        maxBudgetSimulateRequest(),
      );

    expect(groupResult(simulateResponse).failureMessage).toBeTruthy();
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
    const { simulateResponse } =
      await verifier.simulateVerificationWithProofAndSignals(
        { signals, proof },
        maxBudgetSimulateRequest(),
      );

    const budgetUsed = groupResult(simulateResponse).appBudgetConsumed!;

    expect(budgetUsed).toMatchSnapshot("budget used");
    expect(Math.ceil(budgetUsed / LSIG_BUDGET)).toMatchSnapshot(
      "number of lsig txns required for budget",
    );
    expect(Math.ceil(budgetUsed / APP_BUDGET)).toMatchSnapshot(
      "number of app calls required for budget",
    );
  });

  it("works with fullProve", async () => {
    const { simulateResponse } = await verifier.simulateVerification(
      { a: 10, b: 21 },
      maxBudgetSimulateRequest(),
    );

    expect(groupResult(simulateResponse).failedAt).toBeUndefined();
  });
});

describe("groth16 bn254 verifier lsig", () => {
  let verifier: Groth16Bn254LsigVerifier;
  let client: Groth16Bn254SignalsAndProofClient;
  let feePayer: algosdk.AddressWithTransactionSigner;

  beforeAll(async () => {
    feePayer = await localnet.dispenser();

    verifier = new Groth16Bn254LsigVerifier({
      appOffset: 0,
      totalLsigs: 6,
      algod: localnet.algod,
      zKey: "circuit/groth16_bn254_circuit_final.zkey",
      wasmProver: "circuit/circuit_bn254_js/circuit_bn254.wasm",
    });

    const created = await Groth16Bn254SignalsAndProofClient.create.bare({
      algod: localnet.algod,
      sender: feePayer,
    });

    client = created.appClient;
  });

  it("works", async () => {
    const composer = localnet.composer();

    await verifier.verificationParams({
      inputs: { a: 10, b: 21 },
      composer,
      paramsCallback: async (params) => {
        const { lsigParams, args, lsigsUsage } = params;

        // Call app with signals and proof via lsig
        composer.addMethodCall(
          client.params.signalsAndProof({ ...lsigParams, args }),
        );

        // Pay the required fees
        composer.addPayment({
          sender: feePayer,
          receiver: feePayer.address,
          amount: 0n,
          // Its own usage plus the usage the lsigs do not pay for
          maxUsage: BASE_USAGE + lsigsUsage,
        });
      },
    });

    await composer.execute(localnet.algod);
  });

  describe("with sp1 proof", () => {
    // Test vectors generated from SP1 (Succinct Processor 1) zkVM v3.0.0
    // Circuit: simple Fibonacci program (fib(10))
    // Proof system: Groth16 over BN254
    // Generated: 2026-01-15 using sp1-sdk v3.0.0
    //
    // To regenerate:
    // 1. Install SP1 toolchain: cargo install sp1-cli
    // 2. Build program: cd examples/fibonacci && cargo prove build
    // 3. Generate proof: cargo prove --groth16 --bn254
    //
    // These vectors verify that our decoder correctly handles SP1's
    // compressed point format and VK structure.
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

    const proof = decodeGnarkGroth16Bn254Proof(hexToBytes(sp1ProofHex));

    const vk = decodeGnarkGroth16Bn254Vk(hexToBytes(sp1VkHex));

    it("rejects oversized num_k", () => {
      const vkBytes = hexToBytes(sp1VkHex);
      const mutated = new Uint8Array(vkBytes);
      mutated[288] = 0x00;
      mutated[289] = 0x01;
      mutated[290] = 0x00;
      mutated[291] = 0x00;
      expect(() => decodeGnarkGroth16Bn254Vk(mutated)).toThrow(
        "num_k must be <= 1024",
      );
    });

    it("works with app verifier", async () => {
      const sp1App = new Groth16Bn254AppVerifier({
        algod: localnet.algod,
        sender: feePayer,
        vk,
      });

      await sp1App.create({ debugLogging: true });

      const { simulateResponse } =
        await sp1App.simulateVerificationWithProofAndSignals(
          { signals, proof },
          maxBudgetSimulateRequest(),
        );

      expect(groupResult(simulateResponse).failureMessage).toBeFalsy();
    });

    it("rejects invalid uncompressed G1 point in proof", () => {
      const proofBytes = hexToBytes(sp1ProofHex);
      // Corrupt the y-coordinate of pi_a to make it invalid
      // This should fail the curve equation validation
      proofBytes[63] = 0x00;
      proofBytes[62] = 0x00;
      proofBytes[61] = 0x00;
      proofBytes[60] = 0x00;
      expect(() => decodeGnarkGroth16Bn254Proof(proofBytes)).toThrow();
    });

    it("rejects invalid compressed G1 flag in VK", () => {
      const vkBytes = hexToBytes(sp1VkHex);
      // The VK uses compressed format - byte 0 is the G1 alpha point flag
      // Set invalid flag (0x00 instead of 0x80 or 0xc0)
      const mutated = new Uint8Array(vkBytes);
      mutated[0] = 0x00;
      expect(() => decodeGnarkGroth16Bn254Vk(mutated)).toThrow(
        "Invalid G1 point flag",
      );
    });

    it("works with lsig verifier", async () => {
      const sp1Lsig = new Groth16Bn254LsigVerifier({
        totalLsigs: 6,
        appOffset: 0,
        algod: localnet.algod,
        vk,
      });

      const composer = localnet.composer();

      await sp1Lsig.verificationParams({
        proof,
        signals,
        composer,
        paramsCallback: async (params) => {
          const { lsigParams, args, lsigsUsage } = params;

          // Call app with signals and proof via lsig
          composer.addMethodCall(
            client.params.signalsAndProof({ ...lsigParams, args }),
          );

          // Pay the required fees
          composer.addPayment({
            sender: feePayer,
            receiver: feePayer.address,
            amount: 0n,
            // Its own usage plus the usage the lsigs do not pay for
            maxUsage: BASE_USAGE + lsigsUsage,
          });
        },
      });

      await composer.execute(localnet.algod);
    });
  });
});
