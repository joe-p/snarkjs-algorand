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
  type Groth16Bls12381VerificationKey,
  type Groth16Bls12381Proof,
  verifyFromTemplate,
} from "./groth16_bls12381.algo";

import { type PublicSignals } from "./bls12381_common.algo";
import { GTxn } from "@algorandfoundation/algorand-typescript/op";

const APP_OFFSET = TemplateVar<uint64>("APP_OFFSET");

export class Groth16Bls12381VerifierWithLogs extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: Groth16Bls12381VerificationKey): void {}

  verify(signals: PublicSignals, proof: Groth16Bls12381Proof): void {
    assert(verifyFromTemplateWithLogs(signals, proof), "Verification failed");
  }
}

export class Groth16Bls12381Verifier extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: Groth16Bls12381VerificationKey): void {}

  verify(signals: PublicSignals, proof: Groth16Bls12381Proof): void {
    assert(verifyFromTemplate(signals, proof), "Verification failed");
  }
}

export class Groth16Bls12381VerifierLsig extends LogicSig {
  program(): boolean {
    assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });
    const idx: uint64 = Txn.groupIndex + APP_OFFSET;

    const proof = decodeArc4<Groth16Bls12381Proof>(
      GTxn.applicationArgs(idx, 2),
    );
    const signals = decodeArc4<PublicSignals>(GTxn.applicationArgs(idx, 1));

    assert(verifyFromTemplate(signals, proof), "Verification failed");

    return true;
  }
}

export class Groth16Bls12381SignalsAndProof extends Contract {
  public signalsAndProof(
    signals: PublicSignals,
    proof: Groth16Bls12381Proof,
  ): void {}
}
