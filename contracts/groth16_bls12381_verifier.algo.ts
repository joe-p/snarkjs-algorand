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
  type Groth16Bls12381VerificationKey,
  type Groth16Bls12381Proof,
  verifyFromTemplate,
} from "./groth16_bls12381.algo";

import { type PublicSignals } from "./bls12381_common.algo";

export class Groth16Bls12381VerifierWithLogs extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: Groth16Bls12381VerificationKey): void { }

  verify(signals: PublicSignals, proof: Groth16Bls12381Proof): void {
    assert(verifyFromTemplateWithLogs(signals, proof), "Verification failed");
  }
}

export class Groth16Bls12381Verifier extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: Groth16Bls12381VerificationKey): void { }

  verify(signals: PublicSignals, proof: Groth16Bls12381Proof): void {
    assert(verifyFromTemplate(signals, proof), "Verification failed");
  }
}

export class Groth16Bls12381VerifierLsig extends LogicSig {
  program(): boolean {
    assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });

    const proof = decodeArc4<Groth16Bls12381Proof>(Txn.applicationArgs(2));
    const signals = decodeArc4<PublicSignals>(Txn.applicationArgs(1));

    assert(verifyFromTemplate(signals, proof), "Verification failed");

    return true;
  }
}

export class Groth16Bls12381SignalsAndProof extends Contract {
  public signalsAndProof(signals: PublicSignals, proof: Groth16Bls12381Proof): void { }
}
