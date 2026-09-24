import type { Algodv2, SuggestedParams } from "algosdk";
import type { ARC56Contract, BareCreateParams } from "@joe-p/algokit-lite";
import {
  Groth16Bls12381VerifierClient,
  APP_SPEC,
  type Groth16Bls12381Proof,
  type Groth16Bls12381VerificationKey,
} from "../contracts/clients/Groth16Bls12381Verifier";
import {
  Groth16Bls12381VerifierWithLogsClient,
  APP_SPEC as APP_SPEC_WITH_LOGS,
} from "../contracts/clients/Groth16Bls12381VerifierWithLogs";
import {
  Groth16Bn254VerifierClient,
  APP_SPEC as APP_SPEC_BN254,
  type Groth16Bn254Proof,
  type Groth16Bn254VerificationKey,
} from "../contracts/clients/Groth16Bn254Verifier";
import {
  Groth16Bn254VerifierWithLogsClient,
  APP_SPEC as APP_SPEC_BN254_WITH_LOGS,
} from "../contracts/clients/Groth16Bn254VerifierWithLogs";
import * as snarkjs from "snarkjs";
import {
  GROTH16_LSIG_SOURCE,
  GROTH16_BN254_LSIG_SOURCE,
} from "../contracts/out/lsig_source";
import { stringValuesToBigints } from "./index.ts";
import {
  AppVerifier,
  LsigVerifier,
  getABIEncodedValue,
  reorderG2Uncompressed,
  reorderG2UncompressedBN254,
  getProofFromFile,
  type AppVerifierOptions,
  type LsigVerifierOptions,
} from "./common";

// ============================================================================
// Exports
// ============================================================================

export { Groth16Bls12381SignalsAndProofClient } from "../contracts/clients/Groth16Bls12381SignalsAndProof";

export {
  Groth16Bls12381VerifierClient,
  type Groth16Bls12381Proof,
  type Groth16Bls12381VerificationKey,
} from "../contracts/clients/Groth16Bls12381Verifier";

export { Groth16Bls12381VerifierWithLogsClient } from "../contracts/clients/Groth16Bls12381VerifierWithLogs";

export { Groth16Bn254SignalsAndProofClient } from "../contracts/clients/Groth16Bn254SignalsAndProof";

export {
  Groth16Bn254VerifierClient,
  type Groth16Bn254Proof,
  type Groth16Bn254VerificationKey,
} from "../contracts/clients/Groth16Bn254Verifier";

export { Groth16Bn254VerifierWithLogsClient } from "../contracts/clients/Groth16Bn254VerifierWithLogs";

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
    vk_alpha_1,
    vk_beta_2: g2Bytes.vk_beta_2!,
    vk_gamma_2: g2Bytes.vk_gamma_2!,
    vk_delta_2: g2Bytes.vk_delta_2!,
    nPublic: vkey.nPublic,
    IC,
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
    pi_a: proof.pi_aBytes,
    pi_b: piBBytes,
    pi_c: proof.pi_cBytes,
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
  appSpec: ARC56Contract,
): Uint8Array {
  return getABIEncodedValue(appSpec, "Groth16Bls12381VerificationKey", vkey);
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
  constructor(options: LsigVerifierOptions<Groth16Bls12381VerificationKey>) {
    super("bls12381", options);
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<Groth16Bls12381VerificationKey> {
    return getGroth16Bls12381Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: Groth16Bls12381VerificationKey,
    appSpec: ARC56Contract,
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

  protected getAppSpec(): ARC56Contract {
    return APP_SPEC;
  }
}

export class Groth16Bls12381AppVerifier extends AppVerifier<
  Groth16Bls12381VerifierClient,
  Groth16Bls12381Witness,
  Groth16Bls12381VerificationKey
> {
  constructor(options: AppVerifierOptions<Groth16Bls12381VerificationKey>) {
    super("bls12381", options);
  }

  protected async createApp(params: {
    bareParams: Omit<BareCreateParams, "templateVariables">;
    algod: Algodv2;
    getSuggestedParams?: () => Promise<SuggestedParams>;
    vkBytes: Uint8Array;
    debugLogging: boolean;
  }): Promise<Groth16Bls12381VerifierClient> {
    const createParams = {
      ...params.bareParams,
      algod: params.algod,
      getSuggestedParams: params.getSuggestedParams,
      templateVariables: { VERIFICATION_KEY: params.vkBytes },
    };

    if (params.debugLogging) {
      const { appClient } =
        await Groth16Bls12381VerifierWithLogsClient.create.bare(createParams);
      // The logging variant exposes the same verify method, so it stands in
      // for the regular client
      return appClient as unknown as Groth16Bls12381VerifierClient;
    }

    const { appClient } =
      await Groth16Bls12381VerifierClient.create.bare(createParams);
    return appClient;
  }

  protected getAppSpec(debugLogging: boolean): ARC56Contract {
    return debugLogging ? APP_SPEC_WITH_LOGS : APP_SPEC;
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<Groth16Bls12381VerificationKey> {
    return getGroth16Bls12381Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: Groth16Bls12381VerificationKey,
    appSpec: ARC56Contract,
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
  appSpec: ARC56Contract,
): Uint8Array {
  return getABIEncodedValue(appSpec, "Groth16Bn254VerificationKey", vkey);
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
  constructor(options: LsigVerifierOptions<Groth16Bn254VerificationKey>) {
    super("bn254", options);
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<Groth16Bn254VerificationKey> {
    return getGroth16Bn254Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: Groth16Bn254VerificationKey,
    appSpec: ARC56Contract,
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

  protected getAppSpec(): ARC56Contract {
    return APP_SPEC_BN254;
  }
}

export class Groth16Bn254AppVerifier extends AppVerifier<
  Groth16Bn254VerifierClient,
  Groth16Bn254Witness,
  Groth16Bn254VerificationKey
> {
  constructor(options: AppVerifierOptions<Groth16Bn254VerificationKey>) {
    super("bn254", options);
  }

  protected async createApp(params: {
    bareParams: Omit<BareCreateParams, "templateVariables">;
    algod: Algodv2;
    getSuggestedParams?: () => Promise<SuggestedParams>;
    vkBytes: Uint8Array;
    debugLogging: boolean;
  }): Promise<Groth16Bn254VerifierClient> {
    const createParams = {
      ...params.bareParams,
      algod: params.algod,
      getSuggestedParams: params.getSuggestedParams,
      templateVariables: { VERIFICATION_KEY: params.vkBytes },
    };

    if (params.debugLogging) {
      const { appClient } =
        await Groth16Bn254VerifierWithLogsClient.create.bare(createParams);
      // The logging variant exposes the same verify method, so it stands in
      // for the regular client
      return appClient as unknown as Groth16Bn254VerifierClient;
    }

    const { appClient } =
      await Groth16Bn254VerifierClient.create.bare(createParams);
    return appClient;
  }

  protected getAppSpec(debugLogging: boolean): ARC56Contract {
    return debugLogging ? APP_SPEC_BN254_WITH_LOGS : APP_SPEC_BN254;
  }

  protected async getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<Groth16Bn254VerificationKey> {
    return getGroth16Bn254Vkey(zKey, curve);
  }

  protected encodeVkey(
    vk: Groth16Bn254VerificationKey,
    appSpec: ARC56Contract,
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
