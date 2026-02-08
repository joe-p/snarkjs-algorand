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
  Uint256,
} from "@algorandfoundation/algorand-typescript/arc4";
import {
  verifyPlonkFromTemplateWithLogs,
  type PlonkVerificationKey,
  type PlonkProof as PlonkProof,
  verifyPlonkFromTemplate,
} from "./plonk_bls12381.algo";

import { type PublicSignals } from "./bls12381_common.algo";
import { GTxn } from "@algorandfoundation/algorand-typescript/op";

const APP_OFFSET = TemplateVar<uint64>("APP_OFFSET");

export class PlonkVerifierWithLogs extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: PlonkVerificationKey): void {}

  verify(signals: PublicSignals, proof: PlonkProof): void {
    assert(
      verifyPlonkFromTemplateWithLogs(signals, proof),
      "Verification failed",
    );
  }
}

export class PlonkVerifier extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: PlonkVerificationKey): void {}

  verify(signals: PublicSignals, proof: PlonkProof): void {
    assert(verifyPlonkFromTemplate(signals, proof), "Verification failed");
  }
}

export class PlonkVerifierLsig extends LogicSig {
  program(): boolean {
    assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });

    const idx: uint64 = Txn.groupIndex + APP_OFFSET;

    const proof = decodeArc4<PlonkProof>(GTxn.applicationArgs(idx, 2));
    const signals = decodeArc4<PublicSignals>(GTxn.applicationArgs(idx, 1));

    assert(verifyPlonkFromTemplate(signals, proof), "Verification failed");

    return true;
  }
}

export class PlonkSignalsAndProof extends Contract {
  public signalsAndProof(signals: Uint256[], proof: PlonkProof): void {}
}
