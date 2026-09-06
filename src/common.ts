import algosdk, {
  type AddressWithTransactionSigner,
  type Algodv2,
  type SuggestedParams,
  type Transaction,
  type TransactionWithSigner,
} from "algosdk";
import {
  BASE_USAGE,
  Composer,
  getABIType,
  getABIValue,
  type AppClientMethodParams,
  type ARC56Contract,
  type BareCreateParams,
  type MethodParams,
} from "algokit-lite";
import * as snarkjs from "snarkjs";
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

/**
 * ABI encode a value against a type (or struct) declared by an ARC56 contract.
 */
export function getABIEncodedValue(
  arc56: ARC56Contract,
  type: string,
  value: unknown,
): Uint8Array {
  return algosdk.ABIType.from(getABIType(arc56, type)).encode(
    getABIValue(arc56, type, value),
  );
}

/**
 * Substitute `TMPL_` variables into raw TEAL and compile it.
 *
 * The ARC56 app client compiles the programs declared by a contract; the
 * verifier logic signatures are standalone TEAL, so they are compiled here.
 */
export async function compileTealTemplate(
  algod: Algodv2,
  teal: string,
  templateVariables: Record<string, bigint | number | Uint8Array>,
): Promise<Uint8Array> {
  let source = teal;

  for (const [name, value] of Object.entries(templateVariables)) {
    const formatted =
      value instanceof Uint8Array
        ? `0x${Buffer.from(value).toString("hex")}`
        : value.toString();

    source = source.replace(new RegExp(`\\bTMPL_${name}\\b`, "g"), formatted);
  }

  const compiled = await algod.compile(source).do();
  return new Uint8Array(Buffer.from(compiled.result, "base64"));
}

/** Turn a compiled logic signature into something the composer can send from */
export function logicSigAccount(
  program: Uint8Array,
): AddressWithTransactionSigner {
  const account = new algosdk.LogicSigAccount(program);

  return {
    address: account.address(),
    txnSigner: algosdk.makeLogicSigAccountTransactionSigner(account),
  };
}

export type Witness<Proof> = {
  signals: bigint[];
  proof: Proof;
};

/** The parts of a generated verifier client the shared code relies on */
export interface VerifierClient<W extends Witness<unknown>> {
  appId: bigint;
  appAddress: algosdk.Address;
  arc56: ARC56Contract;
  params: {
    verify(
      params: Omit<AppClientMethodParams, "method" | "methodArgs"> & {
        args: W;
      },
    ): MethodParams<void>;
  };
}

export type AppVerifierOptions<VerificationKey> = {
  algod: Algodv2;
  /** Default sender for app creation and verification calls */
  sender: AddressWithTransactionSigner;
  getSuggestedParams?: () => Promise<SuggestedParams>;
} & (
  | {
      zKey: snarkjs.ZKArtifact;
      wasmProver: snarkjs.ZKArtifact;
    }
  | { vk: VerificationKey }
);

export type AppVerifierCreateParams = Omit<
  BareCreateParams,
  "sender" | "templateVariables"
> & {
  sender?: AddressWithTransactionSigner;
  /** Create the verifier variant that logs intermediate values */
  debugLogging?: boolean;
};

export type VerifyCallParams = Omit<
  AppClientMethodParams,
  "method" | "methodArgs" | "onComplete" | "sender"
> & {
  sender?: AddressWithTransactionSigner;
};

export abstract class AppVerifier<
  Client extends VerifierClient<W>,
  W extends Witness<any>,
  VerificationKey,
> {
  appClient?: Client;
  curve?: any;
  vk?: VerificationKey;
  algod: Algodv2;
  sender: AddressWithTransactionSigner;
  getSuggestedParams?: () => Promise<SuggestedParams>;
  zKey?: snarkjs.ZKArtifact;
  wasmProver?: snarkjs.ZKArtifact;

  constructor(
    public curveName: "bls12381" | "bn254",
    options: AppVerifierOptions<VerificationKey>,
  ) {
    this.algod = options.algod;
    this.sender = options.sender;
    this.getSuggestedParams = options.getSuggestedParams;

    if ("vk" in options) {
      this.vk = options.vk;
    } else {
      this.zKey = options.zKey;
      this.wasmProver = options.wasmProver;
    }
  }

  /**
   * Create the app with a bare call, using the logging variant of the contract
   * when `debugLogging` is set. The subclass builds the template variables
   * because their names and types differ per proof system.
   */
  protected abstract createApp(params: {
    bareParams: Omit<BareCreateParams, "templateVariables">;
    algod: Algodv2;
    getSuggestedParams?: () => Promise<SuggestedParams>;
    vk: VerificationKey;
    vkBytes: Uint8Array;
    curve: any;
    debugLogging: boolean;
  }): Promise<Client>;

  /** The ARC56 contract used to encode the verification key */
  protected abstract getAppSpec(debugLogging: boolean): ARC56Contract;

  protected abstract getVkey(
    zKey: snarkjs.ZKArtifact,
    curve: any,
  ): Promise<VerificationKey>;

  protected abstract encodeVkey(
    vk: VerificationKey,
    appSpec: ARC56Contract,
  ): Uint8Array;

  protected abstract encodeProof(proof: any, curve: any): W["proof"];

  protected abstract fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }>;

  private async ensureCurveInstantiation() {
    if (!this.curve) {
      // snarkjs uses "bn128" for BN254 curve
      const snarkjsCurveName =
        this.curveName === "bn254" ? "bn128" : this.curveName;
      // @ts-expect-error curves is not typed
      this.curve = await snarkjs.curves.getCurveFromName(snarkjsCurveName);
    }
  }

  async create(params: AppVerifierCreateParams = {}) {
    if (this.appClient) {
      throw new Error("AppVerifier already created");
    }

    await this.ensureCurveInstantiation();

    if ((!this.zKey || !this.wasmProver) && !this.vk) {
      throw new Error(
        "Must provide either zKey and wasmProver or vk during construction",
      );
    }

    const { debugLogging = false, sender = this.sender, ...rest } = params;

    const vk = this.vk ?? (await this.getVkey(this.zKey!, this.curve));
    const vkBytes = this.encodeVkey(vk, this.getAppSpec(debugLogging));

    this.appClient = await this.createApp({
      bareParams: { ...rest, sender },
      algod: this.algod,
      getSuggestedParams: this.getSuggestedParams,
      vk,
      vkBytes,
      curve: this.curve,
      debugLogging,
    });

    return this.appClient;
  }

  async proofAndSignals(inputs: snarkjs.CircuitSignals): Promise<W> {
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
    } as W;
  }

  private assertCreated(): asserts this is {
    appClient: Client;
  } {
    if (!this.appClient) {
      throw new Error("AppVerifier app has not been created");
    }
  }

  // Methods that take in proof and signals directly

  /** Params for a `verify` call, for composing it into a larger group */
  verifyParams(
    proofAndSignals: W,
    callParams: VerifyCallParams = {},
  ): MethodParams<void> {
    this.assertCreated();

    return this.appClient.params.verify({
      ...callParams,
      sender: callParams.sender ?? this.sender,
      args: proofAndSignals,
    });
  }

  /** A composer holding a single `verify` call */
  private verifyComposer(
    proofAndSignals: W,
    callParams?: VerifyCallParams,
  ): Composer<[void]> {
    return this.composer().addMethodCall(
      this.verifyParams(proofAndSignals, callParams),
    );
  }

  /** A composer for this verifier's algod, to build a group around a `verify` call */
  composer(): Composer {
    return new Composer({
      algod: this.algod,
      getSuggestedParams:
        this.getSuggestedParams ??
        (() => this.algod.getTransactionParams().do()),
    });
  }

  async simulateVerificationWithProofAndSignals(
    proofAndSignals: W,
    request?: algosdk.modelsv2.SimulateRequest,
    callParams?: VerifyCallParams,
  ) {
    return await this.verifyComposer(proofAndSignals, callParams).simulate(
      this.algod,
      request,
    );
  }

  async verifyTransactionFromProofAndSignals(
    proofAndSignals: W,
    callParams?: VerifyCallParams,
  ): Promise<Transaction> {
    const group = await this.verifyComposer(
      proofAndSignals,
      callParams,
    ).buildGroup();

    return group[0]!.txn;
  }

  async callVerifyFromProofAndSignals(
    proofAndSignals: W,
    callParams?: VerifyCallParams,
  ) {
    return await this.verifyComposer(proofAndSignals, callParams).execute(
      this.algod,
    );
  }

  // Methods that generate proof and signals internally

  async simulateVerification(
    inputs: snarkjs.CircuitSignals,
    request?: algosdk.modelsv2.SimulateRequest,
    callParams?: VerifyCallParams,
  ) {
    return this.simulateVerificationWithProofAndSignals(
      await this.proofAndSignals(inputs),
      request,
      callParams,
    );
  }

  async verifyTransaction(
    inputs: snarkjs.CircuitSignals,
    callParams?: VerifyCallParams,
  ): Promise<Transaction> {
    return this.verifyTransactionFromProofAndSignals(
      await this.proofAndSignals(inputs),
      callParams,
    );
  }

  async callVerify(
    inputs: snarkjs.CircuitSignals,
    callParams?: VerifyCallParams,
  ) {
    return this.callVerifyFromProofAndSignals(
      await this.proofAndSignals(inputs),
      callParams,
    );
  }
}

export type LsigVerifierOptions<VerificationKey> = {
  algod: Algodv2;
  /** The number added to the lsig's group index to get the signals and proof from app call index */
  appOffset: number;
  /** The total number of lsigs that will be used to call the app (including the one created by lsigAccount and any extra ones created in verificationParams) */
  totalLsigs: number;
} & (
  | {
      zKey: snarkjs.ZKArtifact;
      wasmProver: snarkjs.ZKArtifact;
    }
  | { vk: VerificationKey }
);

export type LsigVerificationArgs<W extends Witness<any>> = {
  composer: Composer;
  addExtraLsigs?: boolean;
  paramsCallback: (params: {
    lsigParams: {
      sender: AddressWithTransactionSigner;
      staticFee: bigint;
    };
    args: { signals: W["signals"]; proof: W["proof"] };
    /**
     * The usage incurred by the lsig transactions, which pay no fee themselves.
     * Another transaction in the group has to cover it, on top of its own
     * `BASE_USAGE`.
     */
    lsigsUsage: bigint;
    /** The extra lsig transactions, already built and ready to be placed */
    extraLsigsTxns: TransactionWithSigner[];
  }) => Promise<void>;
} & (
  | { inputs: snarkjs.CircuitSignals }
  | { proof: W["proof"]; signals: W["signals"] }
);

export abstract class LsigVerifier<VerificationKey, W extends Witness<any>> {
  curve?: any;
  algod: Algodv2;
  zKey?: snarkjs.ZKArtifact;
  wasmProver?: snarkjs.ZKArtifact;
  totalLsigs: number;
  vk?: VerificationKey;
  appOffset: number;

  constructor(
    public curveName: "bls12381" | "bn254",
    options: LsigVerifierOptions<VerificationKey>,
  ) {
    this.algod = options.algod;
    this.totalLsigs = options.totalLsigs;
    this.appOffset = options.appOffset;

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
    appSpec: ARC56Contract,
  ): Uint8Array;

  protected abstract encodeProof(proof: any, curve: any): W["proof"];

  protected abstract fullProve(
    inputs: snarkjs.CircuitSignals,
    wasmProver: snarkjs.ZKArtifact,
    zKey: snarkjs.ZKArtifact,
  ): Promise<{ proof: any; publicSignals: any }>;

  protected abstract getLsigSource(): string;

  protected abstract getAppSpec(): ARC56Contract;

  protected getAdditionalTemplateVariables(
    vk: VerificationKey,
    curve: any,
  ): Record<string, Uint8Array> {
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

  async proofAndSignals(inputs: snarkjs.CircuitSignals): Promise<W> {
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
    } as W;
  }

  async lsigAccount(): Promise<AddressWithTransactionSigner> {
    await this.ensureCurveInstantiation();

    if (!this.vk && (!this.zKey || !this.wasmProver)) {
      throw new Error(
        "Cannot generate lsig account without either vk or wasmProver and zKey",
      );
    }

    const vk = this.vk ?? (await this.getVkey(this.zKey!, this.curve!));
    const vkBytes = this.encodeVkey(vk, this.getAppSpec());

    const program = await compileTealTemplate(
      this.algod,
      this.getLsigSource(),
      {
        VERIFICATION_KEY: vkBytes,
        APP_OFFSET: this.appOffset,
        ...this.getAdditionalTemplateVariables(vk, this.curve),
      },
    );

    return logicSigAccount(program);
  }

  async verificationParams(args: LsigVerificationArgs<W>): Promise<void> {
    let proof: W["proof"];
    let signals: W["signals"];

    if ("inputs" in args) {
      const proofAndSignals = await this.proofAndSignals(args.inputs);
      proof = proofAndSignals.proof;
      signals = proofAndSignals.signals;
    } else {
      proof = args.proof;
      signals = args.signals;
    }

    const lsigAccount = await this.lsigAccount();

    const extraLsigProgram = await compileTealTemplate(
      this.algod,
      "#pragma version 11\n txn RekeyTo; global ZeroAddress; ==",
      {},
    );
    const extraLsig = logicSigAccount(extraLsigProgram);

    const suggestedParams = {
      ...(await this.algod.getTransactionParams().do()),
      fee: 0n,
      flatFee: true,
    };

    // Built before the callback runs so that it can see them, but only added to
    // the composer afterwards: the lsig reads the app call at its own group
    // index plus appOffset, so the callback's transactions must come first.
    const extraLsigsTxns: TransactionWithSigner[] = [];
    for (let i = 0; i < this.totalLsigs - 1; i++) {
      const lsigPay = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: extraLsig.address,
        receiver: extraLsig.address,
        amount: 0n,
        suggestedParams,
        note: new TextEncoder().encode(
          `Extra lsig ${i + 1} of ${this.totalLsigs - 1}`,
        ),
      });

      extraLsigsTxns.push({ txn: lsigPay, signer: extraLsig.txnSigner });
    }

    await args.paramsCallback({
      lsigParams: {
        sender: lsigAccount,
        staticFee: 0n,
      },
      args: { signals, proof },
      lsigsUsage: BASE_USAGE * BigInt(this.totalLsigs),
      extraLsigsTxns,
    });

    if (args.addExtraLsigs ?? true) {
      for (const { txn, signer } of extraLsigsTxns) {
        args.composer.addTransaction(txn, signer);
      }
    }
  }
}
