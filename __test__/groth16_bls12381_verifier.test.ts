import { describe, it, expect, beforeAll, afterAll } from "vitest";
import algosdk from "algosdk";
import { BASE_USAGE, Localnet } from "algokit-lite";
import * as snarkjs from "snarkjs";
import {
  getGroth16Bls12381Proof,
  Groth16Bls12381AppVerifier,
  Groth16Bls12381LsigVerifier,
} from "../src/groth16";
import { Groth16Bls12381SignalsAndProofClient } from "../contracts/clients/Groth16Bls12381SignalsAndProof";

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

describe("groth16 BLS12-381 verifier", () => {
  let debugVerifier: Groth16Bls12381AppVerifier;
  let verifier: Groth16Bls12381AppVerifier;
  let curve: any;

  beforeAll(async () => {
    const sender = await localnet.dispenser();

    // @ts-expect-error curves is not typed
    curve = await snarkjs.curves.getCurveFromName("bls12381");
    debugVerifier = new Groth16Bls12381AppVerifier({
      algod: localnet.algod,
      sender,
      zKey: "circuit/groth16_circuit_final.zkey",
      wasmProver: "circuit/circuit_js/circuit.wasm",
    });
    await debugVerifier.create({ debugLogging: true });

    verifier = new Groth16Bls12381AppVerifier({
      algod: localnet.algod,
      sender,
      zKey: "circuit/groth16_circuit_final.zkey",
      wasmProver: "circuit/circuit_js/circuit.wasm",
    });
    await verifier.create();
  });

  afterAll(async () => {
    await curve.terminate();
  });

  it("fails with wrong signal", async () => {
    const proof = await getGroth16Bls12381Proof(
      "circuit/groth16_proof.json",
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
    const proof = await getGroth16Bls12381Proof(
      "circuit/groth16_proof.json",
      curve,
    );
    const signals = [
      15744006038856998268181219516291113434365469909648022488288672656450282844855n,
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

describe("groth16 verifier lsig", () => {
  let verifier: Groth16Bls12381LsigVerifier;
  let client: Groth16Bls12381SignalsAndProofClient;
  let feePayer: algosdk.AddressWithTransactionSigner;

  beforeAll(async () => {
    feePayer = await localnet.dispenser();

    verifier = new Groth16Bls12381LsigVerifier({
      appOffset: 0,
      totalLsigs: 6,
      algod: localnet.algod,
      zKey: "circuit/groth16_circuit_final.zkey",
      wasmProver: "circuit/circuit_js/circuit.wasm",
    });

    const created = await Groth16Bls12381SignalsAndProofClient.create.bare({
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
});
