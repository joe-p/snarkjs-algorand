import {
  Contract,
  Global,
  LogicSig,
  TemplateVar,
  Txn,
  arc4,
  assert,
  assertMatch,
  ensureBudget,
  type bytes,
} from "@algorandfoundation/algorand-typescript";
import {
  abimethod,
  decodeArc4,
  Uint256,
} from "@algorandfoundation/algorand-typescript/arc4";
import {
  verifyFromTemplateWithLogs,
  type VerificationKey,
  type PublicSignals,
  type Proof,
  verifyFromTemplate,
  type LagrangeWitness,
  calculateLagrangeEvaluations,
  computeChallenges,
} from "./plonk_bls12381.algo";

export class PlonkVerifierWithLogs extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: VerificationKey): void {}

  verify(signals: PublicSignals, proof: Proof, lw: LagrangeWitness): void {
    assert(
      verifyFromTemplateWithLogs(signals, proof, lw),
      "Verification failed",
    );
  }
}

export class PlonkVerifier extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: VerificationKey): void {}

  verify(signals: PublicSignals, proof: Proof, lw: LagrangeWitness): void {
    assert(verifyFromTemplate(signals, proof, lw), "Verification failed");
  }
}

export class PlonkVerifierLsig extends LogicSig {
  program(): boolean {
    assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });

    const lw = decodeArc4<LagrangeWitness>(Txn.applicationArgs(3));
    const proof = decodeArc4<Proof>(Txn.applicationArgs(2));
    const signals = decodeArc4<Uint256[]>(Txn.applicationArgs(1));

    assert(verifyFromTemplate(signals, proof, lw), "Verification failed");

    return true;
  }
}

export class SignalsAndProof extends Contract {
  public signalsAndProof(
    signals: Uint256[],
    proof: Proof,
    lw: LagrangeWitness,
  ): void {}
}

export class LagrangeWitnessCalculator extends Contract {
  @abimethod({ onCreate: "require", allowActions: "DeleteApplication" })
  public calculateLagrangeWitness(
    signals: PublicSignals,
    proof: Proof,
  ): LagrangeWitness {
    ensureBudget(700 * 250);
    const vkBytes = TemplateVar<bytes>("VERIFICATION_KEY");

    const vk = decodeArc4<VerificationKey>(vkBytes);

    let challenges = computeChallenges(vk, signals, proof);

    const calc = calculateLagrangeEvaluations(challenges, vk);

    return {
      L: calc.L,
      xin: calc.challenges.xin,
      zh: calc.challenges.zh,
    };
  }
}
