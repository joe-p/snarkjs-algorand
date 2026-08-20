import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import * as snarkjs from "snarkjs";
import {
  getPlonkProof,
  PlonkAppVerifier,
  PlonkLsigVerifier,
} from "../src/plonk";
import {
  PlonkSignalsAndProofClient,
  PlonkSignalsAndProofFactory,
} from "../contracts/clients/PlonkSignalsAndProof.ts";

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
  let debugVerifier: PlonkAppVerifier;
  let verifier: PlonkAppVerifier;
  let curve: any;

  beforeAll(async () => {
    const defaultSender = await algorand.account.localNetDispenser();

    // @ts-expect-error curves is not typed
    curve = await snarkjs.curves.getCurveFromName("bls12381");
    debugVerifier = new PlonkAppVerifier({
      algorand,
      zKey: "circuit/plonk_circuit_final.zkey",
      wasmProver: "circuit/circuit_js/circuit.wasm",
    });
    await debugVerifier.deploy({
      appName: `plonk-verifier-${Date.now()}`,
      debugLogging: true,
      defaultSender,
    });

    verifier = new PlonkAppVerifier({
      algorand,
      zKey: "circuit/plonk_circuit_final.zkey",
      wasmProver: "circuit/circuit_js/circuit.wasm",
    });
    await verifier.deploy({
      appName: `plonk-verifier-${Date.now()}`,
      defaultSender,
    });
  });

  afterAll(async () => {
    await curve.terminate();
  });

  it("fails with wrong signal", async () => {
    const proof = await getPlonkProof("circuit/plonk_proof.json", curve);
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

  // The non-logging verifier folds D/F/E into the pairing MSMs, so it is a
  // distinct code path from the logging one and needs its own negative test
  it("fails with wrong signal without logging", async () => {
    const proof = await getPlonkProof("circuit/plonk_proof.json", curve);
    const signals = [1337n];

    const simResult = verifier.simulateVerificationWithProofAndSignals(
      { signals, proof },
      {
        extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
        allowMoreLogging: true,
      },
    );

    await expect(simResult).rejects.toThrow();
  });

  it("works", async () => {
    const proof = await getPlonkProof("circuit/plonk_proof.json", curve);
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
    const proof = await getPlonkProof("circuit/plonk_proof.json", curve);
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

    // NOTE: We no longer calculate D individually and just calculate F in a single MSM
    // expect(logValues.D).toBe(
    //   "dd61360e478901e6bac4c71651b849bd372671aa5d78d357c47359f4d904323557defc9dfec613f47046f451feef11111f88115b918b1de982e3f497c4e725db31f58e7f96a183450300ec570fb193afc770cd5824b4de0d98f0280e865c77a",
    // );

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

// Same circuit as above, but with the input `b` also marked public, so the
// verifier has to handle nPublic == 2: two terms in the beta/gamma transcript,
// two Lagrange evaluations, and a two-term PI(xi).
describe("verifier with 2 public signals", () => {
  const ZKEY = "circuit/plonk_2pub_circuit_final.zkey";
  const WASM_PROVER = "circuit/circuit_2pub_js/circuit_2pub.wasm";
  const PROOF = "circuit/plonk_2pub_proof.json";

  // [c, b] from circuit/plonk_2pub_public.json, for input {a: 3, b: 11}
  const SIGNALS = [
    15744006038856998268181219516291113434365469909648022488288672656450282844855n,
    11n,
  ];

  let debugVerifier: PlonkAppVerifier;
  let verifier: PlonkAppVerifier;
  let curve: any;

  beforeAll(async () => {
    const defaultSender = await algorand.account.localNetDispenser();

    // @ts-expect-error curves is not typed
    curve = await snarkjs.curves.getCurveFromName("bls12381");

    debugVerifier = new PlonkAppVerifier({
      algorand,
      zKey: ZKEY,
      wasmProver: WASM_PROVER,
    });
    await debugVerifier.deploy({
      appName: `plonk-2pub-verifier-${Date.now()}`,
      debugLogging: true,
      defaultSender,
    });

    verifier = new PlonkAppVerifier({
      algorand,
      zKey: ZKEY,
      wasmProver: WASM_PROVER,
    });
    await verifier.deploy({
      appName: `plonk-2pub-verifier-${Date.now()}`,
      defaultSender,
    });
  });

  afterAll(async () => {
    await curve.terminate();
  });

  it("fails with wrong signal", async () => {
    const proof = await getPlonkProof(PROOF, curve);
    const signals = [1337n, 11n];

    const simResult = debugVerifier.simulateVerificationWithProofAndSignals(
      { signals, proof },
      {
        extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
        allowMoreLogging: true,
      },
    );

    await expect(simResult).rejects.toThrow();
  });

  // The non-logging verifier folds D/F/E into the pairing MSMs, so it is a
  // distinct code path from the logging one and needs its own negative test
  it("fails with wrong signal without logging", async () => {
    const proof = await getPlonkProof(PROOF, curve);
    const signals = [1337n, 11n];

    const simResult = verifier.simulateVerificationWithProofAndSignals(
      { signals, proof },
      {
        extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
        allowMoreLogging: true,
      },
    );

    await expect(simResult).rejects.toThrow();
  });

  // A proof for the single-public-signal circuit must not verify here, and vice
  // versa, so the signal count is genuinely bound into the transcript
  it("fails with too few signals", async () => {
    const proof = await getPlonkProof(PROOF, curve);
    const signals = [SIGNALS[0]!];

    const simResult = verifier.simulateVerificationWithProofAndSignals(
      { signals, proof },
      {
        extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
        allowMoreLogging: true,
      },
    );

    await expect(simResult).rejects.toThrow();
  });

  it("works", async () => {
    const proof = await getPlonkProof(PROOF, curve);

    const simResult = await verifier.simulateVerificationWithProofAndSignals(
      { signals: SIGNALS, proof },
      {
        extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
        allowMoreLogging: true,
      },
    );

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
    const proof = await getPlonkProof(PROOF, curve);

    const simResult =
      await debugVerifier.simulateVerificationWithProofAndSignals(
        { signals: SIGNALS, proof },
        {
          extraOpcodeBudget: EXTRA_OPCODE_BUDGET,
          allowMoreLogging: true,
        },
      );
    const logs = simResult.confirmations[0]!.logs!;

    // [INFO]  snarkJS: PLONK VERIFIER STARTED
    // [DEBUG] snarkJS: beta: 3e88978c3fa80eaf3876e6c6502101401ae724226c3551cd30081375401b9965
    // [DEBUG] snarkJS: gamma: 3c7867236fd42c76f6bdd0aa3ad8c89ce9042ab7f98ff345e7c0a4fcd5223e17
    // [DEBUG] snarkJS: alpha: 6972da6af8335e3e66455bd473353e09ed7f6e697e185159054f76cabe1967a4
    // [DEBUG] snarkJS: xi: cff26d3dc53c5b3bb366eaaf9b1f44d3c982539f24b665ac8446dfad582a11
    // [DEBUG] snarkJS: v: 52e3ec47d69ef16d508ee6e1fdc8beede4b2f4fd2e8d2391d2a1c31dba5c79a6
    // [DEBUG] snarkJS: v: 3a2cccf6723f266723662583b48767d38d0e034f909d60145fb80becd2fa56e0
    // [DEBUG] snarkJS: v: 39d3044b894f8a9f2cb6b14a4bcde78508571b3bed28a7730e55cf293f427d4f
    // [DEBUG] snarkJS: v: 19921058429991920e4fd4090abe7157b3945877ec4148c774eea7698e4d9e00
    // [DEBUG] snarkJS: v: 386193ecf13f8d7d75f57cd5478d64fa16a52b3841e8fa33f96dc68abcc8e02e
    // [DEBUG] snarkJS: u: 676888ed1738999aeef65724cd97209c8a5039dd59c41e1bfbd132c7e7883481
    // [DEBUG] snarkJS: L1(xi)=673de404143e19be2b422e7d30b5c7fc84665647e1fe84eddb286f8f88561567
    // [DEBUG] snarkJS: L2(xi)=64176c3c3fd19269e5421b71ef434b7decb5c8d9ebfd0a3a9b6b2594312cc108
    // [DEBUG] snarkJS: PI(xi): 1de2e5dd7064c5d871a699f3c9b34a0b844cc46f764d2cb06d6a03c4f4b84fa8
    // [DEBUG] snarkJS: r0: 894c3c9f38524b77c6ad14c71108ba6c9c6d129440a0869d156ce4ad3e9e55
    // [DEBUG] snarkJS: D: [ b7d7a06edcc8e07e1952582ff26df8bb78e7a4277a263735968eb02dd1a4d39deb2860aaef730a5f76d84adac7297f9, a2cb07be8c1ce5afe58035dd71fa3ae2abcfa1da108fb34fe60cc5b9585d9ec05bed2763b9d63ca4653ceafbbd1864a ]
    // [DEBUG] snarkJS: F: [ 19f2221b0775a3e14dee98fba3d94915df196b9981861725dd569e10ab2cfab617bab9562e5c616ee966fb0322b683d0, 1556e22e8d1848020632fb76c907ec24a7072a8842d10502e3d938ae851770a4ff828bcb47578173aa6a305182356503 ]
    // [DEBUG] snarkJS: E: [ 620d4d502b3070ddc7ac8c56d8c425163d242668b3726e8de0e064beff61f34fbcd1c1ca212c7e53e821af5942e6bed, 17ef2fd2c5bf6bcf01247196964594638285edd6f2449ba1a28551c268a74c03c7ccc6e75e0a7d15b06315af2c0f6219 ]
    // [INFO]  snarkJS: OK!

    const logValues = parseLogs(logs);

    expect(logValues.beta).toBe(
      "3e88978c3fa80eaf3876e6c6502101401ae724226c3551cd30081375401b9965",
    );
    expect(logValues.gamma).toBe(
      "3c7867236fd42c76f6bdd0aa3ad8c89ce9042ab7f98ff345e7c0a4fcd5223e17",
    );
    expect(logValues.alpha).toBe(
      "6972da6af8335e3e66455bd473353e09ed7f6e697e185159054f76cabe1967a4",
    );
    expect(logValues.xi).toBe(
      "cff26d3dc53c5b3bb366eaaf9b1f44d3c982539f24b665ac8446dfad582a11",
    );
    expect(logValues.u).toBe(
      "676888ed1738999aeef65724cd97209c8a5039dd59c41e1bfbd132c7e7883481",
    );

    expect(logValues["v[1]"]).toBe(
      "52e3ec47d69ef16d508ee6e1fdc8beede4b2f4fd2e8d2391d2a1c31dba5c79a6",
    );
    expect(logValues["v[2]"]).toBe(
      "3a2cccf6723f266723662583b48767d38d0e034f909d60145fb80becd2fa56e0",
    );
    expect(logValues["v[3]"]).toBe(
      "39d3044b894f8a9f2cb6b14a4bcde78508571b3bed28a7730e55cf293f427d4f",
    );
    expect(logValues["v[4]"]).toBe(
      "19921058429991920e4fd4090abe7157b3945877ec4148c774eea7698e4d9e00",
    );
    expect(logValues["v[5]"]).toBe(
      "386193ecf13f8d7d75f57cd5478d64fa16a52b3841e8fa33f96dc68abcc8e02e",
    );
    expect(logValues["L1(xi)"]).toBe(
      "673de404143e19be2b422e7d30b5c7fc84665647e1fe84eddb286f8f88561567",
    );

    // The contract does not log L2(xi), but PI(xi) is
    // -(signals[0]*L1 + signals[1]*L2), so it covers the second Lagrange term
    expect(logValues["PI(xi)"]).toBe(
      "1de2e5dd7064c5d871a699f3c9b34a0b844cc46f764d2cb06d6a03c4f4b84fa8",
    );

    expect(logValues.r0).toBe(
      "894c3c9f38524b77c6ad14c71108ba6c9c6d129440a0869d156ce4ad3e9e55",
    );

    expect(logValues.F).toBe(
      "19f2221b0775a3e14dee98fba3d94915df196b9981861725dd569e10ab2cfab617bab9562e5c616ee966fb0322b683d01556e22e8d1848020632fb76c907ec24a7072a8842d10502e3d938ae851770a4ff828bcb47578173aa6a305182356503",
    );

    expect(logValues.E).toBe(
      "620d4d502b3070ddc7ac8c56d8c425163d242668b3726e8de0e064beff61f34fbcd1c1ca212c7e53e821af5942e6bed17ef2fd2c5bf6bcf01247196964594638285edd6f2449ba1a28551c268a74c03c7ccc6e75e0a7d15b06315af2c0f6219",
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

describe("verifier lsig", () => {
  let verifier: PlonkLsigVerifier;
  let algorand: AlgorandClient;
  let client: PlonkSignalsAndProofClient;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    verifier = new PlonkLsigVerifier({
      totalLsigs: 7,
      appOffset: 0,
      algorand,
      zKey: "circuit/plonk_circuit_final.zkey",
      wasmProver: "circuit/circuit_js/circuit.wasm",
    });

    const signalsAndProofFactory = new PlonkSignalsAndProofFactory({
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
        const { lsigParams, lsigsFee, args } = params;

        // Call app with signals and proof via lsig
        group.signalsAndProof({ ...lsigParams, args });

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

// The extra public signal costs opcode budget, so the lsig path needs its own
// coverage to show the work still fits in the same number of logicsigs
describe("verifier lsig with 2 public signals", () => {
  let verifier: PlonkLsigVerifier;
  let algorand: AlgorandClient;
  let client: PlonkSignalsAndProofClient;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    verifier = new PlonkLsigVerifier({
      totalLsigs: 7,
      appOffset: 0,
      algorand,
      zKey: "circuit/plonk_2pub_circuit_final.zkey",
      wasmProver: "circuit/circuit_2pub_js/circuit_2pub.wasm",
    });

    const signalsAndProofFactory = new PlonkSignalsAndProofFactory({
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
        const { lsigParams, lsigsFee, args } = params;

        // Call app with signals and proof via lsig
        group.signalsAndProof({ ...lsigParams, args });

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
