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
import { readFileSync } from "fs";
import type { RawSimulateOptions } from "@algorandfoundation/algokit-utils/types/composer";
import type { Transaction } from "algosdk";
import type { AppClientMethodCallParams } from "@algorandfoundation/algokit-utils/types/app-client";
import algosdk, { OnApplicationComplete, type Address } from "algosdk";
import { LSIG_SOURCE } from "../contracts/out/lsig_source";
import type { AlgoAmount } from "@algorandfoundation/algokit-utils/types/amount";
import {
  LagrangeWitnessCalculatorFactory,
  LagrangeWitnessFromTuple,
  type LagrangeWitness,
} from "../contracts/clients/LagrangeWitnessCalculator";

export {
  PlonkSignalsAndProofFactory,
  PlonkSignalsAndProofClient,
} from "../contracts/clients/PlonkSignalsAndProof.ts";

export type { PlonkProof as OnChainProof } from "../contracts/plonk_bls12381.algo.ts";

function stringValuesToBigints(obj: any): any {
  for (const key in obj) {
    if (typeof obj[key] === "string" && /^\d+$/.test(obj[key])) {
      obj[key] = BigInt(obj[key]);
    } else if (typeof obj[key] === "object" && obj[key] !== null) {
      stringValuesToBigints(obj[key]);
    }
  }
}

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

  const x1 = x2Uncompressed.subarray(0, 48);
  const x0 = x2Uncompressed.subarray(48, 96);
  const y1 = x2Uncompressed.subarray(96, 144);
  const y0 = x2Uncompressed.subarray(144, 192);

  const x2Bytes = new Uint8Array(192);
  x2Bytes.set(x0, 0);
  x2Bytes.set(x1, 48);
  x2Bytes.set(y0, 96);
  x2Bytes.set(y1, 144);

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
  return getABIEncodedValue(vkey, "VerificationKey", appSpec.structs);
}

export async function getPlonkProof(
  path: string,
  curve: any,
): Promise<PlonkProof> {
  const proof = JSON.parse(readFileSync(path, "utf8"));
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

export function encodeSignals(...inputs: string[]) {
  return inputs.map((input) => {
    return BigInt(input);
  });
}

export async function getLagrangeWitness(
  proof: PlonkProof,
  signals: bigint[],
  algorand: AlgorandClient,
  vkBytes: Uint8Array,
  rootOfUnity: Uint8Array,
): Promise<LagrangeWitness> {
  const calcTxn = await new LagrangeWitnessCalculatorFactory({
    algorand,
  }).createTransaction.create.calculateLagrangeWitness({
    args: { proof, signals },
    deployTimeParams: {
      VERIFICATION_KEY: vkBytes,
      ROOT_OF_UNITY: rootOfUnity,
    },
    sender: await algorand.account.localNetDispenser(), // TODO: For mainnet/testnet, use feesink
    onComplete: OnApplicationComplete.DeleteApplicationOC,
  });

  const simResult = await algorand
    .newGroup()
    .addTransaction(calcTxn.transactions[0]!)
    .simulate({
      extraOpcodeBudget: 20_000 * 16,
      skipSignatures: true,
    });

  const log = simResult.confirmations[0]!.logs!.at(-1)!;

  const abiType = algosdk.ABIType.from("(uint256[],uint256,uint256)");

  const retVal = abiType.decode(log.slice(4)) as [bigint[], bigint, bigint];

  return LagrangeWitnessFromTuple(retVal);
}

export type Witness = {
  proof: PlonkProof;
  signals: bigint[];
  lw: {
    l: bigint[];
    xin: bigint;
    zh: bigint;
  };
};

export class PlonkLsigVerifier {
  curve?: any;

  constructor(
    public algorand: AlgorandClient,
    public zKey: snarkjs.ZKArtifact,
    public wasmProver: snarkjs.ZKArtifact,
    public totalLsigs: number = 6,
  ) {}

  private async ensureCurveInstanttiation() {
    if (!this.curve) {
      // @ts-expect-error curves is not typed
      this.curve = await snarkjs.curves.getCurveFromName("bls12381");
    }
  }

  async proofAndSignals(inputs: snarkjs.CircuitSignals): Promise<Witness> {
    await this.ensureCurveInstanttiation();

    const { proof: rawProof, publicSignals: rawSignals } =
      await snarkjs.plonk.fullProve(inputs, this.wasmProver, this.zKey);

    const proof = encodePlonkProof(rawProof, this.curve);
    const signals = encodeSignals(...rawSignals);

    const vk = await getPlonkVkey(this.zKey, this.curve);
    const vkBytes = encodePlonkVk(vk, APP_SPEC);

    const rootOfUnity = Buffer.from(
      this.curve.Fr.toObject(this.curve.Fr.w[Number(vk.power)])
        .toString(16)
        .padStart(64, "0"),
      "hex",
    );

    return {
      proof,
      signals,
      lw: await getLagrangeWitness(
        proof,
        signals,
        this.algorand,
        vkBytes,
        rootOfUnity,
      ),
    };
  }

  async lsigAccount() {
    await this.ensureCurveInstanttiation();

    const vk = await getPlonkVkey(this.zKey, this.curve);
    const vkBytes = encodePlonkVk(vk, APP_SPEC);

    const compilation = await this.algorand.app.compileTealTemplate(
      LSIG_SOURCE,
      {
        VERIFICATION_KEY: vkBytes,
        ROOT_OF_UNITY: Buffer.from(
          this.curve.Fr.toObject(this.curve.Fr.w[Number(vk.power)])
            .toString(16)
            .padStart(64, "0"),
          "hex",
        ),
      },
    );

    return this.algorand.account.logicsig(compilation.compiledBase64ToBytes);
  }

  async verificationParams({
    inputs,
    composer,
    paramsCallback,
    addExtraLsigs = true,
  }: {
    inputs: snarkjs.CircuitSignals;
    composer: {
      addTransaction: (txn: Transaction) => unknown;
    };
    addExtraLsigs?: boolean;
    paramsCallback: (params: {
      appParams: {
        sender: Address;
        staticFee: AlgoAmount;
        args: { signals: bigint[]; proof: PlonkProof; lw: LagrangeWitness };
      };
      lsigsFee: AlgoAmount;
      extraLsigsTxns: Transaction[];
    }) => Promise<void>;
  }): Promise<void> {
    const { proof, signals, lw } = await this.proofAndSignals(inputs);

    const params = {
      appParams: {
        sender: await this.lsigAccount(),
        staticFee: microAlgos(0),
        args: { signals, proof, lw },
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

    await paramsCallback(params);

    for (let i = 0; i < this.totalLsigs - 1; i++) {
      const lsigPay = await this.algorand.createTransaction.payment({
        sender: extraLsig,
        amount: microAlgos(0),
        staticFee: microAlgos(0),
        receiver: extraLsig,
        note: `Extra lsig ${i + 1} of ${this.totalLsigs - 1}`,
      });

      params.extraLsigsTxns.push(lsigPay);

      if (addExtraLsigs) {
        composer.addTransaction(lsigPay);
      }
    }
  }
}

export class PlonkAppVerifier {
  appClient?: PlonkVerifierClient;
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
    params: Omit<PlonkVerifierDeployParams, "deployTimeParams"> & {
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
      factory = new PlonkVerifierWithLogsFactory({
        algorand: this.algorand,
        defaultSender: params.defaultSender,
      });
    } else {
      factory = new PlonkVerifierFactory({
        algorand: this.algorand,
        defaultSender: params.defaultSender,
      });
    }

    const vk = await getPlonkVkey(this.zKey, this.curve);
    const vkBytes = encodePlonkVk(vk, factory.appSpec);

    const rootOfUnity = Buffer.from(
      this.curve.Fr.toObject(this.curve.Fr.w[Number(vk.power)])
        .toString(16)
        .padStart(64, "0"),
      "hex",
    );

    const { appClient } = await factory.deploy({
      ...params,
      deployTimeParams: {
        VERIFICATION_KEY: vkBytes,
        ROOT_OF_UNITY: rootOfUnity,
      },
    });

    this.appClient = appClient;
    return appClient;
  }

  async proofAndSignals(inputs: snarkjs.CircuitSignals): Promise<Witness> {
    await this.ensureCurveInstanttiation();

    const { proof: rawProof, publicSignals: rawSignals } =
      await snarkjs.plonk.fullProve(inputs, this.wasmProver, this.zKey);

    const proof = encodePlonkProof(rawProof, this.curve);
    const signals = encodeSignals(...rawSignals);
    const vk = await getPlonkVkey(this.zKey, this.curve);
    const vkBytes = encodePlonkVk(vk, APP_SPEC);

    const rootOfUnity = Buffer.from(
      this.curve.Fr.toObject(this.curve.Fr.w[Number(vk.power)])
        .toString(16)
        .padStart(64, "0"),
      "hex",
    );

    return {
      proof,
      signals,
      lw: await getLagrangeWitness(
        proof,
        signals,
        this.algorand,
        vkBytes,
        rootOfUnity,
      ),
    };
  }

  private assertDeployed(): asserts this is { appClient: PlonkVerifierClient } {
    if (!this.appClient) {
      throw new Error("AppVerifier not deployed");
    }
  }

  // Methods that take in proof and signals directly

  async simulateVerificationWithProofAndSignals(
    proofAndSignals: { proof: PlonkProof; signals: bigint[] },
    simParams?: RawSimulateOptions,
  ) {
    this.assertDeployed();

    const vk = await getPlonkVkey(this.zKey, this.curve);
    const vkBytes = encodePlonkVk(vk, APP_SPEC);

    const rootOfUnity = Buffer.from(
      this.curve.Fr.toObject(this.curve.Fr.w[Number(vk.power)])
        .toString(16)
        .padStart(64, "0"),
      "hex",
    );

    const lw = await getLagrangeWitness(
      proofAndSignals.proof,
      proofAndSignals.signals,
      this.algorand,
      vkBytes,
      rootOfUnity,
    );
    return this.appClient
      .newGroup()
      .verify({ args: { ...proofAndSignals, lw } })
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
