import { Contract, assert } from "@algorandfoundation/algorand-typescript";
import { abimethod } from "@algorandfoundation/algorand-typescript/arc4";
import {
  verifyFromTemplate,
  type VerificationKey,
  type PublicSignals,
  type Proof,
} from "./plonk_bls12381.algo";

export class PlonkVerifier extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: VerificationKey): void {}

  verify(signals: PublicSignals, proof: Proof): void {
    assert(verifyFromTemplate(signals, proof), "Verification failed");
  }
}
