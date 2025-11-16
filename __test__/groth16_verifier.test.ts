import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import * as snarkjs from "snarkjs";
import {
  getGroth16Proof,
  Groth16AppVerifier,
  Groth16LsigVerifier,
} from "../src/groth16";
import {
  Groth16SignalsAndProofClient,
  Groth16SignalsAndProofFactory,
} from "../contracts/clients/Groth16SignalsAndProof";

const LSIG_BUDGET = 20_000; // Budget for each logicsig
const APP_BUDGET = 700; // Budget for the app call
const GROUP_TXN_SIZE = 16;
const EXTRA_OPCODE_BUDGET = LSIG_BUDGET * GROUP_TXN_SIZE - APP_BUDGET; // Max budget possible with a group of 16 lsigs
const algorand = AlgorandClient.defaultLocalNet();

describe("groth16 verifier", () => {
  let debugVerifier: Groth16AppVerifier;
  let verifier: Groth16AppVerifier;
  let curve: any;

  beforeAll(async () => {
    const defaultSender = await algorand.account.localNetDispenser();

    // @ts-expect-error curves is not typed
    curve = await snarkjs.curves.getCurveFromName("bls12381");
    debugVerifier = new Groth16AppVerifier(
      algorand,
      "circuit/groth16_circuit_final.zkey",
      "circuit/circuit_js/circuit.wasm",
    );
    await debugVerifier.deploy({
      appName: `groth16-verifier-${Date.now()}`,
      debugLogging: true,
      defaultSender,
    });

    verifier = new Groth16AppVerifier(
      algorand,
      "circuit/groth16_circuit_final.zkey",
      "circuit/circuit_js/circuit.wasm",
    );
    await verifier.deploy({
      appName: `groth16-verifier-${Date.now()}`,
      defaultSender,
    });
  });

  afterAll(async () => {
    await curve.terminate();
  });

  it("fails with wrong signal", async () => {
    const proof = await getGroth16Proof("circuit/groth16_proof.json", curve);
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
    const proof = await getGroth16Proof("circuit/groth16_proof.json", curve);
    const signals = [
      15744006038856998268181219516291113434365469909648022488288672656450282844855n,
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

describe("groth16 verifier lsig", () => {
  let verifier: Groth16LsigVerifier;
  let algorand: AlgorandClient;
  let client: Groth16SignalsAndProofClient;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    verifier = new Groth16LsigVerifier(
      algorand,
      "circuit/groth16_circuit_final.zkey",
      "circuit/circuit_js/circuit.wasm",
    );

    const signalsAndProofFactory = new Groth16SignalsAndProofFactory({
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
});
