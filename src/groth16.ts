import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import {
  Groth16VerifierClient,
  Groth16VerifierFactory,
  type Groth16VerifierDeployParams,
  type GrothProof,
  type GrothVerificationKey,
  APP_SPEC,
} from "../contracts/clients/Groth16Verifier";
import { Groth16VerifierWithLogsFactory } from "../contracts/clients/Groth16VerifierWithLogs";
import * as snarkjs from "snarkjs";
import {
  getABIEncodedValue,
  type Arc56Contract,
} from "@algorandfoundation/algokit-utils/types/app-arc56";
import type { Address } from "algosdk";
import { GROTH16_LSIG_SOURCE } from "../contracts/out/lsig_source";
import { stringValuesToBigints } from "./index.ts";
import {
  AppVerifier,
  LsigVerifier,
  reorderG2Uncompressed,
  getProofFromFile,
} from "./common";

export {
  Groth16SignalsAndProofFactory,
  Groth16SignalsAndProofClient,
} from "../contracts/clients/Groth16SignalsAndProof.ts";

export {
  Groth16VerifierClient,
  type GrothProof,
  type GrothVerificationKey,
  type Groth16VerifierDeployParams,
} from "../contracts/clients/Groth16Verifier";

export async function getGroth16Vkey(
  zKey: snarkjs.ZKArtifact,
  curve: any,
): Promise<GrothVerificationKey> {
  const vkey = await snarkjs.zKey.exportVerificationKey(zKey, console);

  // Convert G1 points (IC array + alpha)
  const IC: Uint8Array[] = [];
  for (let i = 0; i <= vkey.nPublic; i++) {
    const icPoint = vkey.IC[i];
    stringValuesToBigints(icPoint);
    const point = curve.G1.fromObject(icPoint);
    IC.push(curve.G1.toUncompressed(point));
  }

  stringValuesToBigints(vkey.vk_alpha_1);
  const alpha1Point = curve.G1.fromObject(vkey.vk_alpha_1);
  const vk_alpha_1 = curve.G1.toUncompressed(alpha1Point);

  // Convert G2 points (beta_2, gamma_2, delta_2)
  const g2Points = ["vk_beta_2", "vk_gamma_2", "vk_delta_2"];
  const g2Bytes: Record<string, Uint8Array> = {};

  for (const pointName of g2Points) {
    stringValuesToBigints(vkey[pointName]);
    const point = curve.G2.fromObject(vkey[pointName]);
    const uncompressed = curve.G2.toUncompressed(point);
    const reordered = reorderG2Uncompressed(uncompressed);

    g2Bytes[pointName] = reordered;
  }

  return {
    vkAlpha_1: vk_alpha_1,
    vkBeta_2: g2Bytes.vk_beta_2!,
    vkGamma_2: g2Bytes.vk_gamma_2!,
    vkDelta_2: g2Bytes.vk_delta_2!,
    nPublic: vkey.nPublic,
    ic: IC,
  };
}

export function encodeGroth16Vk(
  vkey: GrothVerificationKey,
  appSpec: Arc56Contract,
): Uint8Array {
  return getABIEncodedValue(vkey, "GrothVerificationKey", appSpec.structs);
}

export async function getGroth16Proof(
  path: string,
  curve: any,
): Promise<GrothProof> {
  const proof = getProofFromFile(path);
  return encodeGroth16Proof(proof, curve);
}

export function encodeGroth16Proof(proof: any, curve: any): GrothProof {
  // Convert G1 points (pi_a, pi_c)
  ["pi_a", "pi_c"].forEach((p) => {
    stringValuesToBigints(proof[p]);
    const point = curve.G1.fromObject(proof[p]);
    proof[`${p}Bytes`] = curve.G1.toUncompressed(point);
  });

  // Convert G2 point (pi_b)
  stringValuesToBigints(proof.pi_b);
  const piBPoint = curve.G2.fromObject(proof.pi_b);
  const piBUncompressed = curve.G2.toUncompressed(piBPoint);
  const piBBytes = reorderG2Uncompressed(piBUncompressed);

  return {
    piA: proof.pi_aBytes,
    piB: piBBytes,
    piC: proof.pi_cBytes,
  };
}

export type Groth16Witness = {
  proof: GrothProof;
  signals: bigint[];
};

export class Groth16LsigVerifier extends LsigVerifier<
  GrothVerificationKey,
  Groth16Witness
> {
  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<GrothVerificationKey> {
    return getGroth16Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: GrothVerificationKey,
    appSpec: Arc56Contract,
  ): Uint8Array {
    return encodeGroth16Vk(vk, appSpec);
  }

  protected encodeProof(proof: any, curve: any): GrothProof {
    return encodeGroth16Proof(proof, curve);
  }

  protected async fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }> {
    return snarkjs.groth16.fullProve(inputs, wasmProver, zKey);
  }

  protected getLsigSource(): string {
    return GROTH16_LSIG_SOURCE;
  }

  protected getAppSpec(): Arc56Contract {
    return APP_SPEC;
  }
}

export class Groth16AppVerifier extends AppVerifier<
  Groth16VerifierFactory,
  Groth16VerifierWithLogsFactory,
  Groth16VerifierClient,
  Groth16Witness,
  Groth16VerifierDeployParams,
  GrothVerificationKey
> {
  protected newFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): Groth16VerifierFactory {
    return new Groth16VerifierFactory(o);
  }

  protected newLogsFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): Groth16VerifierWithLogsFactory {
    return new Groth16VerifierWithLogsFactory(o);
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<GrothVerificationKey> {
    return getGroth16Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: GrothVerificationKey,
    appSpec: Arc56Contract,
  ): Uint8Array {
    return encodeGroth16Vk(vk, appSpec);
  }

  protected encodeProof(proof: any, curve: any): GrothProof {
    return encodeGroth16Proof(proof, curve);
  }

  protected async fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }> {
    return snarkjs.groth16.fullProve(inputs, wasmProver, zKey);
  }
}
