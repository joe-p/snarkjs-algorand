import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import {
  Groth16Bls12381VerifierClient,
  Groth16Bls12381VerifierFactory,
  type Groth16Bls12381VerifierDeployParams,
  type Groth16Bls12381Proof,
  type Groth16Bls12381VerificationKey,
  APP_SPEC,
} from "../contracts/clients/Groth16Bls12381Verifier";
import { Groth16Bls12381VerifierWithLogsFactory } from "../contracts/clients/Groth16Bls12381VerifierWithLogs";
import {
  Groth16Bn254VerifierClient,
  Groth16Bn254VerifierFactory,
  type Groth16Bn254VerifierDeployParams,
  type Groth16Bn254Proof,
  type Groth16Bn254VerificationKey,
  APP_SPEC as APP_SPEC_BN254,
} from "../contracts/clients/Groth16Bn254Verifier";
import { Groth16Bn254VerifierWithLogsFactory } from "../contracts/clients/Groth16Bn254VerifierWithLogs";
import * as snarkjs from "snarkjs";
import {
  getABIEncodedValue,
  type Arc56Contract,
} from "@algorandfoundation/algokit-utils/types/app-arc56";
import type { Address } from "algosdk";
import {
  GROTH16_LSIG_SOURCE,
  GROTH16_BN254_LSIG_SOURCE,
} from "../contracts/out/lsig_source";
import { stringValuesToBigints } from "./index.ts";
import {
  AppVerifier,
  LsigVerifier,
  reorderG2Uncompressed,
  reorderG2UncompressedBN254,
  getProofFromFile,
} from "./common";

// ============================================================================
// Exports
// ============================================================================

export {
  Groth16Bls12381SignalsAndProofFactory,
  Groth16Bls12381SignalsAndProofClient,
} from "../contracts/clients/Groth16Bls12381SignalsAndProof";

export {
  Groth16Bls12381VerifierClient,
  type Groth16Bls12381Proof,
  type Groth16Bls12381VerificationKey,
  type Groth16Bls12381VerifierDeployParams,
} from "../contracts/clients/Groth16Bls12381Verifier";

export {
  Groth16Bn254SignalsAndProofFactory,
  Groth16Bn254SignalsAndProofClient,
} from "../contracts/clients/Groth16Bn254SignalsAndProof";

export {
  Groth16Bn254VerifierClient,
  type Groth16Bn254Proof,
  type Groth16Bn254VerificationKey,
  type Groth16Bn254VerifierDeployParams,
} from "../contracts/clients/Groth16Bn254Verifier";

// ============================================================================
// Generic Groth16 Helper Functions
// ============================================================================

type G2ReorderFn = (uncompressed: Uint8Array) => Uint8Array;

/**
 * Generic function to get Groth16 verification key from zKey
 * Works for both BLS12-381 and BN254 curves
 */
async function getGroth16VkeyGeneric<T>(
  zKey: snarkjs.ZKArtifact,
  curve: any,
  reorderG2: G2ReorderFn,
): Promise<T> {
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
    g2Bytes[pointName] = reorderG2(uncompressed);
  }

  return {
    vkAlpha_1: vk_alpha_1,
    vkBeta_2: g2Bytes.vk_beta_2!,
    vkGamma_2: g2Bytes.vk_gamma_2!,
    vkDelta_2: g2Bytes.vk_delta_2!,
    nPublic: vkey.nPublic,
    ic: IC,
  } as T;
}

/**
 * Generic function to encode Groth16 proof
 * Works for both BLS12-381 and BN254 curves
 */
function encodeGroth16ProofGeneric<T>(
  proof: any,
  curve: any,
  reorderG2: G2ReorderFn,
): T {
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
  const piBBytes = reorderG2(piBUncompressed);

  return {
    piA: proof.pi_aBytes,
    piB: piBBytes,
    piC: proof.pi_cBytes,
  } as T;
}

// ============================================================================
// BLS12-381 Curve Functions
// ============================================================================

export async function getGroth16Bls12381Vkey(
  zKey: snarkjs.ZKArtifact,
  curve: any,
): Promise<Groth16Bls12381VerificationKey> {
  return getGroth16VkeyGeneric<Groth16Bls12381VerificationKey>(
    zKey,
    curve,
    reorderG2Uncompressed,
  );
}

export function encodeGroth16Bls12381Vk(
  vkey: Groth16Bls12381VerificationKey,
  appSpec: Arc56Contract,
): Uint8Array {
  return getABIEncodedValue(
    vkey,
    "Groth16Bls12381VerificationKey",
    appSpec.structs,
  );
}

export async function getGroth16Bls12381Proof(
  path: string,
  curve: any,
): Promise<Groth16Bls12381Proof> {
  const proof = getProofFromFile(path);
  return encodeGroth16Bls12381Proof(proof, curve);
}

export function encodeGroth16Bls12381Proof(
  proof: any,
  curve: any,
): Groth16Bls12381Proof {
  return encodeGroth16ProofGeneric<Groth16Bls12381Proof>(
    proof,
    curve,
    reorderG2Uncompressed,
  );
}

export type Groth16Bls12381Witness = {
  proof: Groth16Bls12381Proof;
  signals: bigint[];
};

export class Groth16Bls12381LsigVerifier extends LsigVerifier<
  Groth16Bls12381VerificationKey,
  Groth16Bls12381Witness
> {
  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<Groth16Bls12381VerificationKey> {
    return getGroth16Bls12381Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: Groth16Bls12381VerificationKey,
    appSpec: Arc56Contract,
  ): Uint8Array {
    return encodeGroth16Bls12381Vk(vk, appSpec);
  }

  protected encodeProof(proof: any, curve: any): Groth16Bls12381Proof {
    return encodeGroth16Bls12381Proof(proof, curve);
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

export class Groth16Bls12381AppVerifier extends AppVerifier<
  Groth16Bls12381VerifierFactory,
  Groth16Bls12381VerifierWithLogsFactory,
  Groth16Bls12381VerifierClient,
  Groth16Bls12381Witness,
  Groth16Bls12381VerifierDeployParams,
  Groth16Bls12381VerificationKey
> {
  protected newFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): Groth16Bls12381VerifierFactory {
    return new Groth16Bls12381VerifierFactory(o);
  }

  protected newLogsFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): Groth16Bls12381VerifierWithLogsFactory {
    return new Groth16Bls12381VerifierWithLogsFactory(o);
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<Groth16Bls12381VerificationKey> {
    return getGroth16Bls12381Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: Groth16Bls12381VerificationKey,
    appSpec: Arc56Contract,
  ): Uint8Array {
    return encodeGroth16Bls12381Vk(vk, appSpec);
  }

  protected encodeProof(proof: any, curve: any): Groth16Bls12381Proof {
    return encodeGroth16Bls12381Proof(proof, curve);
  }

  protected async fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }> {
    return snarkjs.groth16.fullProve(inputs, wasmProver, zKey);
  }
}

// ============================================================================
// BN254 Curve Functions
// ============================================================================

export async function getGroth16Bn254Vkey(
  zKey: snarkjs.ZKArtifact,
  curve: any,
): Promise<Groth16Bn254VerificationKey> {
  return getGroth16VkeyGeneric<Groth16Bn254VerificationKey>(
    zKey,
    curve,
    reorderG2UncompressedBN254,
  );
}

export function encodeGroth16Bn254Vk(
  vkey: Groth16Bn254VerificationKey,
  appSpec: Arc56Contract,
): Uint8Array {
  return getABIEncodedValue(
    vkey,
    "Groth16Bn254VerificationKey",
    appSpec.structs,
  );
}

export async function getGroth16Bn254Proof(
  path: string,
  curve: any,
): Promise<Groth16Bn254Proof> {
  const proof = getProofFromFile(path);
  return encodeGroth16Bn254Proof(proof, curve);
}

export function encodeGroth16Bn254Proof(
  proof: any,
  curve: any,
): Groth16Bn254Proof {
  return encodeGroth16ProofGeneric<Groth16Bn254Proof>(
    proof,
    curve,
    reorderG2UncompressedBN254,
  );
}

export type Groth16Bn254Witness = {
  proof: Groth16Bn254Proof;
  signals: bigint[];
};

export class Groth16Bn254LsigVerifier extends LsigVerifier<
  Groth16Bn254VerificationKey,
  Groth16Bn254Witness
> {
  constructor(
    algorand: AlgorandClient,
    zKey: snarkjs.ZKArtifact,
    wasmProver: snarkjs.ZKArtifact,
    totalLsigs: number = 6,
  ) {
    super(algorand, zKey, wasmProver, totalLsigs, "bn128");
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<Groth16Bn254VerificationKey> {
    return getGroth16Bn254Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: Groth16Bn254VerificationKey,
    appSpec: Arc56Contract,
  ): Uint8Array {
    return encodeGroth16Bn254Vk(vk, appSpec);
  }

  protected encodeProof(proof: any, curve: any): Groth16Bn254Proof {
    return encodeGroth16Bn254Proof(proof, curve);
  }

  protected async fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }> {
    return snarkjs.groth16.fullProve(inputs, wasmProver, zKey);
  }

  protected getLsigSource(): string {
    return GROTH16_BN254_LSIG_SOURCE;
  }

  protected getAppSpec(): Arc56Contract {
    return APP_SPEC_BN254;
  }
}

export class Groth16Bn254AppVerifier extends AppVerifier<
  Groth16Bn254VerifierFactory,
  Groth16Bn254VerifierWithLogsFactory,
  Groth16Bn254VerifierClient,
  Groth16Bn254Witness,
  Groth16Bn254VerifierDeployParams,
  Groth16Bn254VerificationKey
> {
  constructor(
    algorand: AlgorandClient,
    zKey: snarkjs.ZKArtifact,
    wasmProver: snarkjs.ZKArtifact,
  ) {
    super(algorand, zKey, wasmProver, "bn128");
  }

  protected newFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): Groth16Bn254VerifierFactory {
    return new Groth16Bn254VerifierFactory(o);
  }

  protected newLogsFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): Groth16Bn254VerifierWithLogsFactory {
    return new Groth16Bn254VerifierWithLogsFactory(o);
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<Groth16Bn254VerificationKey> {
    return getGroth16Bn254Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: Groth16Bn254VerificationKey,
    appSpec: Arc56Contract,
  ): Uint8Array {
    return encodeGroth16Bn254Vk(vk, appSpec);
  }

  protected encodeProof(proof: any, curve: any): Groth16Bn254Proof {
    return encodeGroth16Bn254Proof(proof, curve);
  }

  protected async fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }> {
    return snarkjs.groth16.fullProve(inputs, wasmProver, zKey);
  }
}
