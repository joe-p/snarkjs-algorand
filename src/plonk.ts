import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import {
  PlonkVerifierClient,
  PlonkVerifierFactory,
  type PlonkVerifierDeployParams,
  type PlonkProof,
  type PlonkVerificationKey,
  APP_SPEC,
} from "../contracts/clients/PlonkVerifier";
import { PlonkVerifierWithLogsFactory } from "../contracts/clients/PlonkVerifierWithLogs";
import * as snarkjs from "snarkjs";
import {
  getABIEncodedValue,
  type Arc56Contract,
} from "@algorandfoundation/algokit-utils/types/app-arc56";
import type { Transaction } from "algosdk";
import { type Address } from "algosdk";
import { PLONK_LSIG_SOURCE } from "../contracts/out/lsig_source";
import type { AlgoAmount } from "@algorandfoundation/algokit-utils/types/amount";
import { stringValuesToBigints } from "./index.ts";
import {
  AppVerifier,
  LsigVerifier,
  encodeSignals,
  reorderG2Uncompressed,
  getProofFromFile,
  type AppVerifierOptions,
  type LsigVerifierOptions,
} from "./common";

export {
  PlonkSignalsAndProofFactory,
  PlonkSignalsAndProofClient,
} from "../contracts/clients/PlonkSignalsAndProof.ts";

export {
  PlonkVerifierClient,
  type PlonkProof,
  type PlonkVerificationKey,
  type PlonkVerifierDeployParams,
} from "../contracts/clients/PlonkVerifier";

export async function getPlonkVkey(
  zKey: snarkjs.ZKArtifact,
  curve: any,
): Promise<PlonkVerificationKey> {
  const vkey = await snarkjs.zKey.exportVerificationKey(zKey, console);

  ["Ql", "Qr", "Qo", "Qm", "Qc", "S1", "S2", "S3"].forEach((p) => {
    stringValuesToBigints(vkey[p]);
    const point = curve.G1.fromObject(vkey[p]);
    vkey[`${p}Bytes`] = curve.G1.toUncompressed(point);
  });

  stringValuesToBigints(vkey.X_2);
  const x2Point = curve.G2.fromObject(vkey.X_2);
  const x2Uncompressed = curve.G2.toUncompressed(x2Point);
  const x2Bytes = reorderG2Uncompressed(x2Uncompressed);

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
    x_2: x2Bytes,
  };
}

export function encodePlonkVk(
  vkey: PlonkVerificationKey,
  appSpec: Arc56Contract,
): Uint8Array {
  return getABIEncodedValue(vkey, "PlonkVerificationKey", appSpec.structs);
}

export async function getPlonkProof(
  path: string,
  curve: any,
): Promise<PlonkProof> {
  const proof = getProofFromFile(path);
  return encodePlonkProof(proof, curve);
}

export function encodePlonkProof(proof: any, curve: any): PlonkProof {
  ["A", "B", "C", "Z", "T1", "T2", "T3", "Wxi", "Wxiw"].forEach((p) => {
    stringValuesToBigints(proof[p]);
    const point = curve.G1.fromObject(proof[p]);
    proof[`${p}Bytes`] = curve.G1.toUncompressed(point);
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

export function encodePlonkSignals(...inputs: string[]) {
  return encodeSignals(...inputs);
}

export type PlonkWitness = {
  proof: PlonkProof;
  signals: bigint[];
};

export class PlonkLsigVerifier extends LsigVerifier<
  PlonkVerificationKey,
  PlonkWitness
> {
  constructor(o: LsigVerifierOptions<PlonkVerificationKey>) {
    if (o.totalLsigs === undefined) {
      o.totalLsigs = 7;
    }
    super("bls12381", o);
  }
  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<PlonkVerificationKey> {
    return getPlonkVkey(zKey, curve);
  }

  protected encodeVkey(
    vk: PlonkVerificationKey,
    appSpec: Arc56Contract,
  ): Uint8Array {
    return encodePlonkVk(vk, appSpec);
  }

  protected encodeProof(proof: any, curve: any): PlonkProof {
    return encodePlonkProof(proof, curve);
  }

  protected encodeSignals(...signals: string[]): bigint[] {
    return encodePlonkSignals(...signals);
  }

  protected async fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }> {
    return snarkjs.plonk.fullProve(inputs, wasmProver, zKey);
  }

  protected getLsigSource(): string {
    return PLONK_LSIG_SOURCE;
  }

  protected getAppSpec(): Arc56Contract {
    return APP_SPEC;
  }

  protected override getAdditionalTemplateParams(
    vk: PlonkVerificationKey,
    curve: any,
  ): Record<string, any> {
    const rootOfUnity = Buffer.from(
      curve.Fr.toObject(curve.Fr.w[Number(vk.power)])
        .toString(16)
        .padStart(64, "0"),
      "hex",
    );

    return {
      ROOT_OF_UNITY: rootOfUnity,
    };
  }
}

export class PlonkAppVerifier extends AppVerifier<
  PlonkVerifierFactory,
  PlonkVerifierWithLogsFactory,
  PlonkVerifierClient,
  PlonkWitness,
  PlonkVerifierDeployParams,
  PlonkVerificationKey
> {
  constructor(o: AppVerifierOptions<PlonkVerificationKey>) {
    super("bls12381", o);
  }

  protected newFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): PlonkVerifierFactory {
    return new PlonkVerifierFactory(o);
  }

  protected newLogsFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): PlonkVerifierWithLogsFactory {
    return new PlonkVerifierWithLogsFactory(o);
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<PlonkVerificationKey> {
    return getPlonkVkey(zKey, curve);
  }

  protected encodeVkey(
    vk: PlonkVerificationKey,
    appSpec: Arc56Contract,
  ): Uint8Array {
    return encodePlonkVk(vk, appSpec);
  }

  protected encodeProof(proof: any, curve: any): PlonkProof {
    return encodePlonkProof(proof, curve);
  }

  protected async fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }> {
    return snarkjs.plonk.fullProve(inputs, wasmProver, zKey);
  }

  protected override getAdditionalDeployParams(
    vk: PlonkVerificationKey,
    curve: any,
  ): Record<string, any> {
    const rootOfUnity = Buffer.from(
      curve.Fr.toObject(curve.Fr.w[Number(vk.power)])
        .toString(16)
        .padStart(64, "0"),
      "hex",
    );

    return {
      ROOT_OF_UNITY: rootOfUnity,
    };
  }
}
