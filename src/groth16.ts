import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import {
  Groth16VerifierClient,
  Groth16VerifierFactory,
  type Groth16VerifierDeployParams,
  type GrothProof,
  type GrothVerificationKey,
} from "../contracts/clients/Groth16Verifier";
import { Groth16VerifierWithLogsFactory } from "../contracts/clients/Groth16VerifierWithLogs";
import * as snarkjs from "snarkjs";
import {
  getABIEncodedValue,
  type Arc56Contract,
} from "@algorandfoundation/algokit-utils/types/app-arc56";
import { readFileSync } from "fs";
import type { RawSimulateOptions } from "@algorandfoundation/algokit-utils/types/composer";
import type { Transaction } from "algosdk";
import type { AppClientMethodCallParams } from "@algorandfoundation/algokit-utils/types/app-client";
import type { Address } from "algosdk";
import { stringValuesToBigints } from "./index.ts";

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

    // Reorder G2 point components from [x1, x0, y1, y0] to [x0, x1, y0, y1]
    const x1 = uncompressed.subarray(0, 48);
    const x0 = uncompressed.subarray(48, 96);
    const y1 = uncompressed.subarray(96, 144);
    const y0 = uncompressed.subarray(144, 192);

    const reordered = new Uint8Array(192);
    reordered.set(x0, 0);
    reordered.set(x1, 48);
    reordered.set(y0, 96);
    reordered.set(y1, 144);

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
  const proof = JSON.parse(readFileSync(path, "utf8"));
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

  // Reorder G2 point components from [x1, x0, y1, y0] to [x0, x1, y0, y1]
  const x1 = piBUncompressed.subarray(0, 48);
  const x0 = piBUncompressed.subarray(48, 96);
  const y1 = piBUncompressed.subarray(96, 144);
  const y0 = piBUncompressed.subarray(144, 192);

  const piBBytes = new Uint8Array(192);
  piBBytes.set(x0, 0);
  piBBytes.set(x1, 48);
  piBBytes.set(y0, 96);
  piBBytes.set(y1, 144);

  return {
    piA: proof.pi_aBytes,
    piB: piBBytes,
    piC: proof.pi_cBytes,
  };
}

export function encodeGroth16Signals(...inputs: string[]) {
  return inputs.map((input) => {
    return BigInt(input);
  });
}

export type Groth16Witness = {
  proof: GrothProof;
  signals: bigint[];
};

export class Groth16AppVerifier {
  appClient?: Groth16VerifierClient;
  curve?: any;

  constructor(
    public algorand: AlgorandClient,
    public zKey: snarkjs.ZKArtifact,
    public wasmProver: snarkjs.ZKArtifact,
  ) {}

  private async ensureCurveInstanttiation() {
    if (!this.curve) {
      // @ts-expect-error curves is not typed
      this.curve = await snarkjs.curves.getCurveFromName("bls12381");
    }
  }

  async deploy(
    params: Omit<Groth16VerifierDeployParams, "deployTimeParams"> & {
      defaultSender: Address;
      debugLogging?: boolean;
    },
  ) {
    if (this.appClient) {
      throw new Error("AppVerifier already deployed");
    }

    await this.ensureCurveInstanttiation();

    let factory;

    if (params.debugLogging) {
      factory = new Groth16VerifierWithLogsFactory({
        algorand: this.algorand,
        defaultSender: params.defaultSender,
      });
    } else {
      factory = new Groth16VerifierFactory({
        algorand: this.algorand,
        defaultSender: params.defaultSender,
      });
    }

    const vk = await getGroth16Vkey(this.zKey, this.curve);
    const vkBytes = encodeGroth16Vk(vk, factory.appSpec);

    const { appClient } = await factory.deploy({
      ...params,
      deployTimeParams: {
        VERIFICATION_KEY: vkBytes,
      },
    });

    this.appClient = appClient;
    return appClient;
  }

  async proofAndSignals(
    inputs: snarkjs.CircuitSignals,
  ): Promise<Groth16Witness> {
    await this.ensureCurveInstanttiation();

    const { proof: rawProof, publicSignals: rawSignals } =
      await snarkjs.groth16.fullProve(inputs, this.wasmProver, this.zKey);

    const proof = encodeGroth16Proof(rawProof, this.curve);
    const signals = encodeGroth16Signals(...rawSignals);

    return {
      proof,
      signals,
    };
  }

  private assertDeployed(): asserts this is {
    appClient: Groth16VerifierClient;
  } {
    if (!this.appClient) {
      throw new Error("AppVerifier not deployed");
    }
  }

  // Methods that take in proof and signals directly

  async simulateVerificationWithProofAndSignals(
    proofAndSignals: { proof: GrothProof; signals: bigint[] },
    simParams?: RawSimulateOptions,
  ) {
    this.assertDeployed();

    return this.appClient
      .newGroup()
      .verify({ args: proofAndSignals })
      .simulate(simParams ?? {});
  }

  async verifyTransactionFromProofAndSignals(
    proofAndSignals: Groth16Witness,
  ): Promise<Transaction> {
    this.assertDeployed();

    return (
      await this.appClient.createTransaction.verify({
        args: proofAndSignals,
      })
    ).transactions[0]!;
  }

  async callVerifyFromProofAndSignals(
    proofAndSignals: Groth16Witness,
    callParams?: Omit<
      AppClientMethodCallParams,
      "method" | "args" | "onComplete"
    >,
  ) {
    this.assertDeployed();

    return this.appClient.send.verify({ ...callParams, args: proofAndSignals });
  }

  // Methods that generate proof and signals internally

  async simulateVerification(
    inputs: snarkjs.CircuitSignals,
    simParams?: RawSimulateOptions,
  ) {
    return this.simulateVerificationWithProofAndSignals(
      await this.proofAndSignals(inputs),
      simParams,
    );
  }

  async verifyTransaction(
    inputs: snarkjs.CircuitSignals,
  ): Promise<Transaction> {
    return this.verifyTransactionFromProofAndSignals(
      await this.proofAndSignals(inputs),
    );
  }

  async callVerify(
    inputs: snarkjs.CircuitSignals,
    callParams?: Omit<
      AppClientMethodCallParams,
      "method" | "args" | "onComplete"
    >,
  ) {
    return this.callVerifyFromProofAndSignals(
      await this.proofAndSignals(inputs),
      callParams,
    );
  }
}
