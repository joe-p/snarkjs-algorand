import {
  Contract,
  Global,
  LogicSig,
  TemplateVar,
  Txn,
  assert,
  assertMatch,
  type uint64,
} from "@algorandfoundation/algorand-typescript";
import {
  abimethod,
  decodeArc4,
} from "@algorandfoundation/algorand-typescript/arc4";
import {
  verifyFromTemplateWithLogs,
  type Groth16Bn254VerificationKey,
  type Groth16Bn254Proof,
  verifyFromTemplate,
} from "./groth16_bn254.algo";

import { type PublicSignals } from "./bn254_common.algo";
import { GTxn } from "@algorandfoundation/algorand-typescript/op";

const APP_OFFSET = TemplateVar<uint64>("APP_OFFSET");

export class Groth16Bn254VerifierWithLogs extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: Groth16Bn254VerificationKey): void {}

  verify(signals: PublicSignals, proof: Groth16Bn254Proof): void {
    assert(verifyFromTemplateWithLogs(signals, proof), "Verification failed");
  }
}

export class Groth16Bn254Verifier extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: Groth16Bn254VerificationKey): void {}

  verify(signals: PublicSignals, proof: Groth16Bn254Proof): void {
    assert(verifyFromTemplate(signals, proof), "Verification failed");
  }
}

export class Groth16Bn254VerifierLsig extends LogicSig {
  program(): boolean {
    assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });
    const idx: uint64 = Txn.groupIndex + APP_OFFSET;

    const proof = decodeArc4<Groth16Bn254Proof>(GTxn.applicationArgs(idx, 2));
    const signals = decodeArc4<PublicSignals>(GTxn.applicationArgs(idx, 1));

    assert(verifyFromTemplate(signals, proof), "Verification failed");

    return true;
  }
}

export class Groth16Bn254SignalsAndProof extends Contract {
  public signalsAndProof(
    signals: PublicSignals,
    proof: Groth16Bn254Proof,
  ): void {}
}
