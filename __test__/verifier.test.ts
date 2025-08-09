import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import {
  PlonkVerifierClient,
  PlonkVerifierFactory,
  type Proof,
  type VerificationKey,
} from "../contracts/clients/PlonkVerifier";
import * as snarkjs from "snarkjs";
import { readFileSync } from "fs";

const algorand = AlgorandClient.defaultLocalNet();

function stringValuesToBigints(obj: any): any {
  for (const key in obj) {
    if (typeof obj[key] === "string" && /^\d+$/.test(obj[key])) {
      obj[key] = BigInt(obj[key]);
    } else if (typeof obj[key] === "object" && obj[key] !== null) {
      stringValuesToBigints(obj[key]);
    }
  }
}

async function getVkey(path: string, curve: any): Promise<VerificationKey> {
  const vkey = await snarkjs.zKey.exportVerificationKey(path, console);

  ["Ql", "Qr", "Qo", "Qm", "Qc", "S1", "S2", "S3"].forEach((p) => {
    const buffer = new Uint8Array(96);
    stringValuesToBigints(vkey[p]);
    const point = curve.G1.fromObject(vkey[p]);
    curve.G1.toRprUncompressed(buffer, 0, point);
    vkey[`${p}Bytes`] = buffer;
  });

  return {
    power: vkey.power,
    nPublic: vkey.nPublic,
    ql: vkey.QlBytes,
    qr: vkey.QrBytes,
    qo: vkey.QoBytes,
    qm: vkey.QmBytes,
    qc: vkey.QcBytes,
    s1: vkey.S1Bytes,
    s2: vkey.S2Bytes,
    s3: vkey.S3Bytes,
    k1: BigInt(vkey.k1),
    k2: BigInt(vkey.k2),
  };
}

async function getProof(path: string, curve: any): Promise<Proof> {
  const proof = JSON.parse(readFileSync(path, "utf8"));

  ["A", "B", "C", "Z", "T1", "T2", "T3", "Wxi", "Wxiw"].forEach((p) => {
    const buffer = new Uint8Array(96);
    stringValuesToBigints(proof[p]);
    const point = curve.G1.fromObject(proof[p]);
    curve.G1.toRprUncompressed(buffer, 0, point);
    proof[`${p}Bytes`] = buffer;
  });

  ["eval_a", "eval_b", "eval_c", "eval_s1", "eval_s2", "eval_zw"].forEach(
    (p) => {
      proof[`${p}BigInt`] = BigInt(proof[p]);
    },
  );

  return {
    a: proof.ABytes,
    b: proof.BBytes,
    c: proof.CBytes,
    z: proof.ZBytes,
    t1: proof.T1Bytes,
    t2: proof.T2Bytes,
    t3: proof.T3Bytes,
    wxi: proof.WxiBytes,
    wxiw: proof.WxiwBytes,
    evalA: proof.eval_aBigInt,
    evalB: proof.eval_bBigInt,
    evalC: proof.eval_cBigInt,
    evalS1: proof.eval_s1BigInt,
    evalS2: proof.eval_s2BigInt,
    evalZw: proof.eval_zwBigInt,
  };
}

function encodeSignals(...inputs: bigint[]) {
  return inputs.map((input) => {
    return BigInt(input);
  });
}

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
};

function parseLogs(logs: Uint8Array[]): LogValues {
  const values: LogValues = {};
  let currentKey = Buffer.from(logs[0]!).toString();

  for (let i = 1; i < logs.length; i++) {
    if (currentKey.length) {
      values[currentKey as keyof LogValues] = Buffer.from(logs[i]!)
        .toString("hex")
        .replace(/^0+/, ""); // trim leading zeros
      currentKey = "";
    } else {
      currentKey = Buffer.from(logs[i]!).toString();
    }
  }
  return values;
}

describe("verifier", () => {
  let client: PlonkVerifierClient;
  let curve: any;

  beforeAll(async () => {
    const defaultSender = await algorand.account.localNetDispenser();
    const factory = new PlonkVerifierFactory({ algorand, defaultSender });
    const { appClient } = await factory.deploy({
      appName: Math.random().toString(16),
    });
    client = appClient;
    curve = await snarkjs.curves.getCurveFromName("bls12381");
  });

  afterAll(async () => {
    await curve.terminate();
  });

  it("works", async () => {
    const vk = await getVkey("circuit/circuit_final.zkey", curve);
    const proof = await getProof("circuit/proof.json", curve);
    const signals =
      encodeSignals(
        15744006038856998268181219516291113434365469909648022488288672656450282844855n,
      );
    const group = client.newGroup().verify({ args: { vk, signals, proof } });

    // We are testing using an app so we can log, so we need to increase the opcode budget
    const lsigBudget = 20_000;
    const simResult = await group.simulate({
      // Keeping track of how many lsigs are needed for each step:
      // r0: 2
      // D: 4
      extraOpcodeBudget: 4 * lsigBudget - 700,
      allowMoreLogging: true,
    });
    const logs = simResult.confirmations[0]!.logs!;

    const logValues = parseLogs(logs);

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
    // TODO: [DEBUG] snarkJS: F: [ 18463acd328baa605062c9ce3cceb2982e0fc4b3031c7b75872324ce6941321b73e7c06f70d1b3f9b44d37c74c4b2b01, ebd2a44a0be8eb548ad8846225e22b06048ff7de2f78ceb51a1e86994bcb93afdaff78c20b143b7ff4b5d3a8469848 ]
    // [DEBUG] snarkJS: E: [ 10be434db7820f39ab40a95a54bbc57d673fffd3bdadbef08de0e5f8bc5e206a82f63d1fb3e12892601c220b51a8ef5f, 90f264a0a62778fccb84713818c856cf1156b61c90ae5968632b902b3101c51243629cab527a6cf23fa491e8478f35d ]
    // [INFO]  snarkJS: OK!

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
  });
});
