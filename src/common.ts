import type { AlgorandClient } from "@algorandfoundation/algokit-utils";
import type { Address, Transaction } from "algosdk";
import type {
  Groth16Bls12381VerifierFactory,
  Groth16Bls12381VerificationKey,
} from "../contracts/clients/Groth16Bls12381Verifier";
import type { Groth16Bls12381VerifierWithLogsFactory } from "../contracts/clients/Groth16Bls12381VerifierWithLogs";
import type {
  PlonkVerifierFactory,
  PlonkVerificationKey,
} from "../contracts/clients/PlonkVerifier";
import type { PlonkVerifierWithLogsFactory } from "../contracts/clients/PlonkVerifierWithLogs";
import type { RawSimulateOptions } from "@algorandfoundation/algokit-utils/types/composer";
import type { AppClientMethodCallParams } from "@algorandfoundation/algokit-utils/types/app-client";
import type { Groth16Bls12381Witness, PlonkWitness } from ".";
import * as snarkjs from "snarkjs";
import { microAlgos } from "@algorandfoundation/algokit-utils";
import type { AlgoAmount } from "@algorandfoundation/algokit-utils/types/amount";
import type { Arc56Contract } from "@algorandfoundation/algokit-utils/types/app-arc56";
import { readFileSync } from "fs";

export function encodeSignals(...inputs: string[]): bigint[] {
  return inputs.map((input) => BigInt(input));
}

export function reorderG2Uncompressed(uncompressed: Uint8Array): Uint8Array {
  const x1 = uncompressed.subarray(0, 48);
  const x0 = uncompressed.subarray(48, 96);
  const y1 = uncompressed.subarray(96, 144);
  const y0 = uncompressed.subarray(144, 192);

  const reordered = new Uint8Array(192);
  reordered.set(x0, 0);
  reordered.set(x1, 48);
  reordered.set(y0, 96);
  reordered.set(y1, 144);

  return reordered;
}

export function reorderG2UncompressedBN254(
  uncompressed: Uint8Array,
): Uint8Array {
  const x1 = uncompressed.subarray(0, 32);
  const x0 = uncompressed.subarray(32, 64);
  const y1 = uncompressed.subarray(64, 96);
  const y0 = uncompressed.subarray(96, 128);

  const reordered = new Uint8Array(128);
  reordered.set(x0, 0);
  reordered.set(x1, 32);
  reordered.set(y0, 64);
  reordered.set(y1, 96);

  return reordered;
}

export function getProofFromFile(path: string): any {
  return JSON.parse(readFileSync(path, "utf8"));
}

export type AppVerifierOptions<VerificationKey> = {
  algorand: AlgorandClient;
} & (
  | {
      zKey: snarkjs.ZKArtifact;
      wasmProver: snarkjs.ZKArtifact;
    }
  | { vk: VerificationKey }
);

export abstract class AppVerifier<
  Factory extends Groth16Bls12381VerifierFactory | PlonkVerifierFactory,
  LogsFactory extends
    | Groth16Bls12381VerifierWithLogsFactory
    | PlonkVerifierWithLogsFactory,
  Client extends ReturnType<Factory["getAppClientById"]>,
  Witness extends { signals: any; proof: any } & Parameters<
    Client["send"]["verify"]
  >[0]["args"],
  DeployTimeParams extends Parameters<Factory["deploy"]>[0],
  VerificationKey extends ({ _vk: any } & Parameters<
    Client["send"]["closeOut"]["_dummy"]
  >[0]["args"])["_vk"],
> {
  appClient?: Client;
  curve?: any;
  vk?: VerificationKey;
  algorand: AlgorandClient;
  zKey?: snarkjs.ZKArtifact;
  wasmProver?: snarkjs.ZKArtifact;

  constructor(
    public curveName: "bls12381" | "bn254",
    options: AppVerifierOptions<VerificationKey>,
  ) {
    this.algorand = options.algorand;

    if ("vk" in options) {
      this.vk = options.vk;
    } else {
      this.zKey = options.zKey;
      this.wasmProver = options.wasmProver;
    }
  }

  protected abstract newFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): Factory;

  protected abstract newLogsFactory(o: {
    algorand: AlgorandClient;
    defaultSender: Address;
  }): LogsFactory;

  protected abstract getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<VerificationKey>;

  protected abstract encodeVkey(
    vk: VerificationKey,
    appSpec: Factory["appSpec"],
  ): Uint8Array;

  protected abstract encodeProof(proof: any, curve: any): Witness["proof"];

  protected abstract fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }>;

  protected getAdditionalDeployParams(
    vk: VerificationKey,
    curve: any,
  ): Record<string, any> {
    return {};
  }

  private async ensureCurveInstantiation() {
    if (!this.curve) {
      // snarkjs uses "bn128" for BN254 curve
      const snarkjsCurveName =
        this.curveName === "bn254" ? "bn128" : this.curveName;
      // @ts-expect-error curves is not typed
      this.curve = await snarkjs.curves.getCurveFromName(snarkjsCurveName);
    }
  }

  async deploy(
    params: Omit<DeployTimeParams, "deployTimeParams"> & {
      defaultSender: Address;
      debugLogging?: boolean;
    },
  ) {
    if (this.appClient) {
      throw new Error("AppVerifier already deployed");
    }

    await this.ensureCurveInstantiation();

    let factory;

    if (params.debugLogging) {
      factory = this.newLogsFactory({
        algorand: this.algorand,
        defaultSender: params.defaultSender,
      });
    } else {
      factory = this.newFactory({
        algorand: this.algorand,
        defaultSender: params.defaultSender,
      });
    }

    if ((!this.zKey || !this.wasmProver) && !this.vk) {
      throw new Error(
        "Must provide either zKey and wasmProver or vk during construction",
      );
    }

    const vk = this.vk ?? (await this.getVkey(this.zKey!, this.curve));
    const vkBytes = this.encodeVkey(vk, factory.appSpec);

    const additionalParams = this.getAdditionalDeployParams(vk, this.curve);

    const { appClient } = await factory.deploy({
      ...params,
      deployTimeParams: {
        VERIFICATION_KEY: vkBytes,
        ...additionalParams,
      },
    });

    this.appClient = appClient as Client;
    return appClient;
  }

  async proofAndSignals(inputs: snarkjs.CircuitSignals): Promise<Witness> {
    await this.ensureCurveInstantiation();

    if (!this.wasmProver || !this.zKey) {
      throw new Error(
        "Cannot generate proof and signals without wasmProver and zKey",
      );
    }

    const { proof: rawProof, publicSignals: rawSignals } = await this.fullProve(
      inputs,
      this.wasmProver,
      this.zKey,
    );

    const proof = this.encodeProof(rawProof, this.curve);
    const signals = encodeSignals(...rawSignals);

    return {
      proof,
      signals,
    } as Witness;
  }

  private assertDeployed(): asserts this is {
    appClient: Client;
  } {
    if (!this.appClient) {
      throw new Error("AppVerifier not deployed");
    }
  }

  // Methods that take in proof and signals directly

  async simulateVerificationWithProofAndSignals(
    proofAndSignals: Witness,
    simParams?: RawSimulateOptions,
  ) {
    this.assertDeployed();

    return this.appClient
      .newGroup()
      .verify({ args: proofAndSignals })
      .simulate(simParams ?? {});
  }

  async verifyTransactionFromProofAndSignals(
    proofAndSignals: Witness,
  ): Promise<Transaction> {
    this.assertDeployed();

    return (
      await this.appClient.createTransaction.verify({
        args: proofAndSignals,
      })
    ).transactions[0]!;
  }

  async callVerifyFromProofAndSignals(
    proofAndSignals: Witness,
    callParams?: Omit<
      AppClientMethodCallParams,
      "method" | "args" | "onComplete"
    >,
  ) {
    this.assertDeployed();

    return this.appClient.send.verify({
      ...callParams,
      args: proofAndSignals,
    });
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

export type LsigVerifierOptions<VerificationKey> =
  AppVerifierOptions<VerificationKey> & {
    totalLsigs?: number;
  };

export type LsigVerificationArgs<Witness extends Record<string, any>> = {
  composer: {
    addTransaction: (txn: Transaction) => unknown;
  };
  addExtraLsigs?: boolean;
  paramsCallback: (params: {
    appParams: {
      sender: Address;
      staticFee: AlgoAmount;
      args: { signals: Witness["signals"]; proof: Witness["proof"] };
    };
    lsigsFee: AlgoAmount;
    extraLsigsTxns: Transaction[];
  }) => Promise<void>;
} & (
  | { inputs: snarkjs.CircuitSignals }
  | { proof: Witness["proof"]; signals: Witness["signals"] }
);

export abstract class LsigVerifier<
  VerificationKey extends Groth16Bls12381VerificationKey | PlonkVerificationKey,
  Witness extends Groth16Bls12381Witness | PlonkWitness,
> {
  curve?: any;
  algorand: AlgorandClient;
  zKey?: snarkjs.ZKArtifact;
  wasmProver?: snarkjs.ZKArtifact;
  totalLsigs: number;
  vk?: VerificationKey;

  constructor(
    public curveName: "bls12381" | "bn254",
    options: LsigVerifierOptions<VerificationKey>,
  ) {
    this.algorand = options.algorand;
    this.totalLsigs = options.totalLsigs ?? 6;

    if ("vk" in options) {
      this.vk = options.vk;
    } else {
      this.zKey = options.zKey;
      this.wasmProver = options.wasmProver;
    }
  }

  protected abstract getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<VerificationKey>;

  protected abstract encodeVkey(
    vk: VerificationKey,
    appSpec: Arc56Contract,
  ): Uint8Array;

  protected abstract encodeProof(proof: any, curve: any): Witness["proof"];

  protected abstract fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }>;

  protected abstract getLsigSource(): string;

  protected abstract getAppSpec(): Arc56Contract;

  protected getAdditionalTemplateParams(
    vk: VerificationKey,
    curve: any,
  ): Record<string, any> {
    return {};
  }

  private async ensureCurveInstantiation() {
    if (!this.curve) {
      // snarkjs uses "bn128" for BN254 curve
      const snarkjsCurveName =
        this.curveName === "bn254" ? "bn128" : this.curveName;
      // @ts-expect-error curves is not typed
      this.curve = await snarkjs.curves.getCurveFromName(snarkjsCurveName);
    }
  }

  async proofAndSignals(inputs: snarkjs.CircuitSignals): Promise<Witness> {
    await this.ensureCurveInstantiation();

    if (!this.wasmProver || !this.zKey) {
      throw new Error(
        "Cannot generate proof and signals without wasmProver and zKey",
      );
    }

    const { proof: rawProof, publicSignals: rawSignals } = await this.fullProve(
      inputs,
      this.wasmProver,
      this.zKey,
    );

    const proof = this.encodeProof(rawProof, this.curve);
    const signals = encodeSignals(...rawSignals);

    return {
      proof,
      signals,
    } as Witness;
  }

  async lsigAccount() {
    await this.ensureCurveInstantiation();

    if (!this.vk && (!this.zKey || !this.wasmProver)) {
      throw new Error(
        "Cannot generate lsig account without either vk or wasmProver and zKey",
      );
    }

    const vk = this.vk ?? (await this.getVkey(this.zKey!, this.curve!));
    const vkBytes = this.encodeVkey(vk, this.getAppSpec());

    const additionalParams = this.getAdditionalTemplateParams(vk, this.curve);

    const compilation = await this.algorand.app.compileTealTemplate(
      this.getLsigSource(),
      {
        VERIFICATION_KEY: vkBytes,
        ...additionalParams,
      },
    );

    return this.algorand.account.logicsig(compilation.compiledBase64ToBytes);
  }

  async verificationParams(args: LsigVerificationArgs<Witness>): Promise<void> {
    let proof: Witness["proof"];
    let signals: Witness["signals"];

    if ("inputs" in args) {
      const proofAndSignals = await this.proofAndSignals(args.inputs);
      proof = proofAndSignals.proof;
      signals = proofAndSignals.signals;
    } else {
      proof = args.proof;
      signals = args.signals;
    }

    const params = {
      appParams: {
        sender: await this.lsigAccount(),
        staticFee: microAlgos(0),
        args: { signals: signals, proof: proof },
      },
      lsigsFee: microAlgos(1000 * this.totalLsigs),
      extraLsigsTxns: [] as Transaction[],
    };

    const compilation = await this.algorand.app.compileTeal(
      "#pragma version 11\n txn RekeyTo; global ZeroAddress; ==",
    );
    const extraLsig = this.algorand.account.logicsig(
      compilation.compiledBase64ToBytes,
    );

    await args.paramsCallback(params);

    for (let i = 0; i < this.totalLsigs - 1; i++) {
      const lsigPay = await this.algorand.createTransaction.payment({
        sender: extraLsig,
        amount: microAlgos(0),
        staticFee: microAlgos(0),
        receiver: extraLsig,
        note: `Extra lsig ${i + 1} of ${this.totalLsigs - 1}`,
      });

      params.extraLsigsTxns.push(lsigPay);

      if (args.addExtraLsigs ?? true) {
        args.composer.addTransaction(lsigPay);
      }
    }
  }
}
