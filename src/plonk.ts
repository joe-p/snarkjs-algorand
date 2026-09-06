import type { Algodv2, SuggestedParams } from "algosdk";
import type { ARC56Contract, BareCreateParams } from "algokit-lite";
import {
  PlonkVerifierClient,
  APP_SPEC,
  type PlonkProof,
  type PlonkVerificationKey,
} from "../contracts/clients/PlonkVerifier";
import {
  PlonkVerifierWithLogsClient,
  APP_SPEC as APP_SPEC_WITH_LOGS,
} from "../contracts/clients/PlonkVerifierWithLogs";
import * as snarkjs from "snarkjs";
import { PLONK_LSIG_SOURCE } from "../contracts/out/lsig_source";
import { stringValuesToBigints } from "./index.ts";
import {
  AppVerifier,
  LsigVerifier,
  encodeSignals,
  getABIEncodedValue,
  reorderG2Uncompressed,
  getProofFromFile,
  type AppVerifierOptions,
  type LsigVerifierOptions,
} from "./common";

export { PlonkSignalsAndProofClient } from "../contracts/clients/PlonkSignalsAndProof.ts";

export {
  PlonkVerifierClient,
  type PlonkProof,
  type PlonkVerificationKey,
} from "../contracts/clients/PlonkVerifier";

export { PlonkVerifierWithLogsClient } from "../contracts/clients/PlonkVerifierWithLogs";

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
    Ql: vkey.QlBytes,
    Qr: vkey.QrBytes,
    Qo: vkey.QoBytes,
    Qm: vkey.QmBytes,
    Qc: vkey.QcBytes,
    S1: vkey.S1Bytes,
    S2: vkey.S2Bytes,
    S3: vkey.S3Bytes,
    k1: BigInt(vkey.k1),
    k2: BigInt(vkey.k2),
    X_2: x2Bytes,
  };
}

export function encodePlonkVk(
  vkey: PlonkVerificationKey,
  appSpec: ARC56Contract,
): Uint8Array {
  return getABIEncodedValue(appSpec, "PlonkVerificationKey", vkey);
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
    A: proof.ABytes,
    B: proof.BBytes,
    C: proof.CBytes,
    Z: proof.ZBytes,
    T1: proof.T1Bytes,
    T2: proof.T2Bytes,
    T3: proof.T3Bytes,
    Wxi: proof.WxiBytes,
    Wxiw: proof.WxiwBytes,
    eval_a: proof.eval_aBigInt,
    eval_b: proof.eval_bBigInt,
    eval_c: proof.eval_cBigInt,
    eval_s1: proof.eval_s1BigInt,
    eval_s2: proof.eval_s2BigInt,
    eval_zw: proof.eval_zwBigInt,
  };
}

export function encodePlonkSignals(...inputs: string[]) {
  return encodeSignals(...inputs);
}

export type PlonkWitness = {
  proof: PlonkProof;
  signals: bigint[];
};

/**
 * The root of unity for the circuit's domain size, which the verifier needs
 * alongside the verification key.
 */
function rootOfUnity(vk: PlonkVerificationKey, curve: any): Uint8Array {
  return new Uint8Array(
    Buffer.from(
      curve.Fr.toObject(curve.Fr.w[Number(vk.power)])
        .toString(16)
        .padStart(64, "0"),
      "hex",
    ),
  );
}

export class PlonkLsigVerifier extends LsigVerifier<
  PlonkVerificationKey,
  PlonkWitness
> {
  constructor(o: LsigVerifierOptions<PlonkVerificationKey>) {
    const options: LsigVerifierOptions<PlonkVerificationKey> = {
      ...o,
      totalLsigs: o.totalLsigs ?? 7,
    };
    super("bls12381", options);
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<PlonkVerificationKey> {
    return getPlonkVkey(zKey, curve);
  }

  protected encodeVkey(
    vk: PlonkVerificationKey,
    appSpec: ARC56Contract,
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

  protected getAppSpec(): ARC56Contract {
    return APP_SPEC;
  }

  protected override getAdditionalTemplateVariables(
    vk: PlonkVerificationKey,
    curve: any,
  ): Record<string, Uint8Array> {
    return { ROOT_OF_UNITY: rootOfUnity(vk, curve) };
  }
}

export class PlonkAppVerifier extends AppVerifier<
  PlonkVerifierClient,
  PlonkWitness,
  PlonkVerificationKey
> {
  constructor(o: AppVerifierOptions<PlonkVerificationKey>) {
    super("bls12381", o);
  }

  protected async createApp(params: {
    bareParams: Omit<BareCreateParams, "templateVariables">;
    algod: Algodv2;
    getSuggestedParams?: () => Promise<SuggestedParams>;
    vk: PlonkVerificationKey;
    vkBytes: Uint8Array;
    curve: any;
    debugLogging: boolean;
  }): Promise<PlonkVerifierClient> {
    const createParams = {
      ...params.bareParams,
      algod: params.algod,
      getSuggestedParams: params.getSuggestedParams,
      templateVariables: {
        VERIFICATION_KEY: params.vkBytes,
        ROOT_OF_UNITY: rootOfUnity(params.vk, params.curve),
      },
    };

    if (params.debugLogging) {
      const { appClient } =
        await PlonkVerifierWithLogsClient.create.bare(createParams);
      // The logging variant exposes the same verify method, so it stands in
      // for the regular client
      return appClient as unknown as PlonkVerifierClient;
    }

    const { appClient } = await PlonkVerifierClient.create.bare(createParams);
    return appClient;
  }

  protected getAppSpec(debugLogging: boolean): ARC56Contract {
    return debugLogging ? APP_SPEC_WITH_LOGS : APP_SPEC;
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<PlonkVerificationKey> {
    return getPlonkVkey(zKey, curve);
  }

  protected encodeVkey(
    vk: PlonkVerificationKey,
    appSpec: ARC56Contract,
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
}
