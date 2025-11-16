import {
  Contract,
  Global,
  LogicSig,
  Txn,
  assert,
  assertMatch,
} from "@algorandfoundation/algorand-typescript";
import {
  abimethod,
  decodeArc4,
} from "@algorandfoundation/algorand-typescript/arc4";
import {
  verifyFromTemplateWithLogs,
  type VerificationKey,
  type Proof,
  verifyFromTemplate,
} from "./groth16_bls12381.algo";

import { type PublicSignals } from "./bls12381_common.algo";

export class Groth16VerifierWithLogs extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: VerificationKey): void {}

  verify(signals: PublicSignals, proof: Proof): void {
    assert(
      verifyFromTemplateWithLogs(signals, proof),
      "Verification failed",
    );
  }
}

export class Groth16Verifier extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: VerificationKey): void {}

  verify(signals: PublicSignals, proof: Proof): void {
    assert(verifyFromTemplate(signals, proof), "Verification failed");
  }
}

export class Groth16VerifierLsig extends LogicSig {
  program(): boolean {
    assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });

    const proof = decodeArc4<Proof>(Txn.applicationArgs(2));
    const signals = decodeArc4<PublicSignals>(Txn.applicationArgs(1));

    assert(verifyFromTemplate(signals, proof), "Verification failed");

    return true;
  }
}

export class Groth16SignalsAndProof extends Contract {
  public signalsAndProof(signals: PublicSignals, proof: Proof): void {}
}
