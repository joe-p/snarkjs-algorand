import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import * as snarkjs from "snarkjs";
import { getProof, AppVerifier } from "../src/index";

const LSIG_BUDGET = 20_000; // Budget for each logicsig
const APP_BUDGET = 700; // Budget for the app call
const GROUP_TXN_SIZE = 16;
const EXTRA_OPCODE_BUDGET = LSIG_BUDGET * GROUP_TXN_SIZE - APP_BUDGET; // Max budget possible with a group of 16 lsigs
const algorand = AlgorandClient.defaultLocalNet();

type LogValues = {
  beta?: string;
  gamma?: string;
  alpha?: string;
  xi?: string;
  u?: string;
  "v[1]"?: string;
  "v[2]"?: string;
  "v[3]"?: string;
  "v[4]"?: string;
  "v[5]"?: string;
  "L1(xi)"?: string;
  "PI(xi)"?: string;
  r0?: string;
  D?: string;
  F?: string;
  E?: string;
};

// snarkjs removes leading zeros when logging BE bigints, so we need to do the same
function logValueToHex(log: Uint8Array): string {
  return Buffer.from(log).toString("hex").replace(/^0+/, ""); // trim leading zeros
}

function parseLogs(logs: Uint8Array[]): LogValues {
  const values: LogValues = {};
  let currentKey = Buffer.from(logs[0]!).toString();

  for (let i = 1; i < logs.length; i++) {
    if (currentKey.length) {
      if (logs[i]!.length === 96) {
        values[currentKey as keyof LogValues] = [
          logs[i]!.subarray(0, 48),
          logs[i]!.subarray(48),
        ]
          .map((part) => logValueToHex(part))
          .join("");
      } else {
        values[currentKey as keyof LogValues] = logValueToHex(logs[i]!);
      }
      currentKey = "";
    } else {
      currentKey = Buffer.from(logs[i]!).toString();
    }
  }
  return values;
}

describe("verifier", () => {
  let debugVerifier: AppVerifier;
  let verifier: AppVerifier;
  let curve: any;

  beforeAll(async () => {
    const defaultSender = await algorand.account.localNetDispenser();

    // @ts-expect-error curves is not typed
    curve = await snarkjs.curves.getCurveFromName("bls12381");
    debugVerifier = new AppVerifier(
      algorand,
      "circuit/circuit_final.zkey",
      "circuit/circuit_js/circuit.wasm",
    );
    await debugVerifier.deploy({
      appName: `plonk-verifier-${Date.now()}`,
      debugLogging: true,
      defaultSender,
    });

    verifier = new AppVerifier(
      algorand,
      "circuit/circuit_final.zkey",
      "circuit/circuit_js/circuit.wasm",
    );
    await verifier.deploy({
      appName: `plonk-verifier-${Date.now()}`,
      defaultSender,
    });
  });

  afterAll(async () => {
    await curve.terminate();
  });

  it("fails with wrong signal", async () => {
    const proof = await getProof("circuit/proof.json", curve);
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
    const proof = await getProof("circuit/proof.json", curve);
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

  it("works with logging", async () => {
    const proof = await getProof("circuit/proof.json", curve);
    const signals = [
      15744006038856998268181219516291113434365469909648022488288672656450282844855n,
    ];

    // We are testing using an app so we can log, so we need to increase the opcode budget
    const simResult =
      await debugVerifier.simulateVerificationWithProofAndSignals(
        { signals, proof },
        {
          extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
          allowMoreLogging: true,
        },
      );
    const logs = simResult.confirmations[0]!.logs!;

    simResult.simulateResponse.txnGroups[0]?.appBudgetConsumed;

    // [INFO]  snarkJS: PLONK VERIFIER STARTED
    // [DEBUG] snarkJS: beta: 2dcf3fb1a062e6a514fac1ceda05eb7216c0232888eb5ca21a2325ad39ba0ee3
    // [DEBUG] snarkJS: gamma: e4246114e15f9cc6230795032c30683cfc845963ce77623efbb1311f035811b
    // [DEBUG] snarkJS: alpha: d0390731fa65b90268f8459bab9de6776b03b46a43adc175fb08049b45a9619
    // [DEBUG] snarkJS: xi: 2026e55fc47b4ec928d3bc2e01d92e4d4043946b99bc745185b65ed3f0bd933d
    // [DEBUG] snarkJS: v: 89d98a650d439b9852740a193a1b5ec70ed6f0d0d515cd49bc733f3fbf0cfed
    // [DEBUG] snarkJS: v: 443e60017edb0ee42aa27a695cbf065e6987fb35c2a37ebd6e5ba51dadcf9dce
    // [DEBUG] snarkJS: v: 4ea572119b187403d75f7ae24a554854c3321e32a2d3cccf7a00d52bcb7bdad7
    // [DEBUG] snarkJS: v: 4bd56b8fd54c2ed4b4693dcb0861e01ba2e561d275dc6f90ff29a288bfa60fd9
    // [DEBUG] snarkJS: v: 41872ee42918178985969341dc816357f68cedc65ba30e27edba311d4467f125
    // [DEBUG] snarkJS: u: 3c70fe64a05ab41df31da73b94fd93a1464f37c6d40a04d65a2dd2d7f2419fad
    // [DEBUG] snarkJS: L1(xi)=46dd60f8923d7d9990aff309366db4e39dc56e83bb35fa326d610da2ac5e8496
    // [DEBUG] snarkJS: PI(xi): 7327379bca9fd93517e06c5ad56a0891962b170320bafd11010e8c5e9cdf9e56
    // [DEBUG] snarkJS: r0: 5e47e3760437353a648d5bb09e7cc190e141ddf993d6e9d073afe5e48fa3d006
    // [DEBUG] snarkJS: D: [ dd61360e478901e6bac4c71651b849bd372671aa5d78d357c47359f4d904323557defc9dfec613f47046f451feef111, 11f88115b918b1de982e3f497c4e725db31f58e7f96a183450300ec570fb193afc770cd5824b4de0d98f0280e865c77a ]
    // [DEBUG] snarkJS: F: [ 18463acd328baa605062c9ce3cceb2982e0fc4b3031c7b75872324ce6941321b73e7c06f70d1b3f9b44d37c74c4b2b01, ebd2a44a0be8eb548ad8846225e22b06048ff7de2f78ceb51a1e86994bcb93afdaff78c20b143b7ff4b5d3a8469848 ]
    // [DEBUG] snarkJS: E: [ 10be434db7820f39ab40a95a54bbc57d673fffd3bdadbef08de0e5f8bc5e206a82f63d1fb3e12892601c220b51a8ef5f, 90f264a0a62778fccb84713818c856cf1156b61c90ae5968632b902b3101c51243629cab527a6cf23fa491e8478f35d ]
    // [INFO]  snarkJS: OK!

    const logValues = parseLogs(logs);

    expect(logValues.beta).toBe(
      "2dcf3fb1a062e6a514fac1ceda05eb7216c0232888eb5ca21a2325ad39ba0ee3",
    );
    expect(logValues.gamma).toBe(
      "e4246114e15f9cc6230795032c30683cfc845963ce77623efbb1311f035811b",
    );
    expect(logValues.alpha).toBe(
      "d0390731fa65b90268f8459bab9de6776b03b46a43adc175fb08049b45a9619",
    );
    expect(logValues.xi).toBe(
      "2026e55fc47b4ec928d3bc2e01d92e4d4043946b99bc745185b65ed3f0bd933d",
    );
    expect(logValues.u).toBe(
      "3c70fe64a05ab41df31da73b94fd93a1464f37c6d40a04d65a2dd2d7f2419fad",
    );

    expect(logValues["v[1]"]).toBe(
      "89d98a650d439b9852740a193a1b5ec70ed6f0d0d515cd49bc733f3fbf0cfed",
    );
    expect(logValues["v[2]"]).toBe(
      "443e60017edb0ee42aa27a695cbf065e6987fb35c2a37ebd6e5ba51dadcf9dce",
    );
    expect(logValues["v[3]"]).toBe(
      "4ea572119b187403d75f7ae24a554854c3321e32a2d3cccf7a00d52bcb7bdad7",
    );
    expect(logValues["v[4]"]).toBe(
      "4bd56b8fd54c2ed4b4693dcb0861e01ba2e561d275dc6f90ff29a288bfa60fd9",
    );
    expect(logValues["v[5]"]).toBe(
      "41872ee42918178985969341dc816357f68cedc65ba30e27edba311d4467f125",
    );
    expect(logValues["L1(xi)"]).toBe(
      "46dd60f8923d7d9990aff309366db4e39dc56e83bb35fa326d610da2ac5e8496",
    );

    expect(logValues["PI(xi)"]).toBe(
      "7327379bca9fd93517e06c5ad56a0891962b170320bafd11010e8c5e9cdf9e56",
    );

    expect(logValues.r0).toBe(
      "5e47e3760437353a648d5bb09e7cc190e141ddf993d6e9d073afe5e48fa3d006",
    );

    expect(logValues.D).toBe(
      "dd61360e478901e6bac4c71651b849bd372671aa5d78d357c47359f4d904323557defc9dfec613f47046f451feef11111f88115b918b1de982e3f497c4e725db31f58e7f96a183450300ec570fb193afc770cd5824b4de0d98f0280e865c77a",
    );

    expect(logValues.F).toBe(
      "18463acd328baa605062c9ce3cceb2982e0fc4b3031c7b75872324ce6941321b73e7c06f70d1b3f9b44d37c74c4b2b01ebd2a44a0be8eb548ad8846225e22b06048ff7de2f78ceb51a1e86994bcb93afdaff78c20b143b7ff4b5d3a8469848",
    );

    expect(logValues.E).toBe(
      "10be434db7820f39ab40a95a54bbc57d673fffd3bdadbef08de0e5f8bc5e206a82f63d1fb3e12892601c220b51a8ef5f90f264a0a62778fccb84713818c856cf1156b61c90ae5968632b902b3101c51243629cab527a6cf23fa491e8478f35d",
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
