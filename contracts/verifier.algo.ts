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
  convertBytes,
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
  decodeVk,
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

    // export type Proof = {
    //   // Uncompressed G1 points
    //   A: bytes<96>;
    //   B: bytes<96>;
    //   C: bytes<96>;
    //   Z: bytes<96>;
    //   T1: bytes<96>;
    //   T2: bytes<96>;
    //   T3: bytes<96>;
    //   Wxi: bytes<96>;
    //   Wxiw: bytes<96>;
    //   // Field evaluations are 32 bytes (SNARKJS internal representation, BE)
    //   eval_a: Uint256;
    //   eval_b: Uint256;
    //   eval_c: Uint256;
    //   eval_s1: Uint256;
    //   eval_s2: Uint256;
    //   eval_zw: Uint256;
    // };
    const proofBytes = Txn.applicationArgs(2);
    const proof: Proof = {
      A: proofBytes.slice(0, 96).toFixed({ length: 96 }),
      B: proofBytes.slice(96, 192).toFixed({ length: 96 }),
      C: proofBytes.slice(192, 288).toFixed({ length: 96 }),
      Z: proofBytes.slice(288, 384).toFixed({ length: 96 }),
      T1: proofBytes.slice(384, 480).toFixed({ length: 96 }),
      T2: proofBytes.slice(480, 576).toFixed({ length: 96 }),
      T3: proofBytes.slice(576, 672).toFixed({ length: 96 }),
      Wxi: proofBytes.slice(672, 768).toFixed({ length: 96 }),
      Wxiw: proofBytes.slice(768, 864).toFixed({ length: 96 }),
      eval_a: convertBytes<Uint256>(proofBytes.slice(864, 896), {
        strategy: "unsafe-cast",
      }),
      eval_b: convertBytes<Uint256>(proofBytes.slice(896, 928), {
        strategy: "unsafe-cast",
      }),
      eval_c: convertBytes<Uint256>(proofBytes.slice(928, 960), {
        strategy: "unsafe-cast",
      }),
      eval_s1: convertBytes<Uint256>(proofBytes.slice(960, 992), {
        strategy: "unsafe-cast",
      }),
      eval_s2: convertBytes<Uint256>(proofBytes.slice(992, 1024), {
        strategy: "unsafe-cast",
      }),
      eval_zw: convertBytes<Uint256>(proofBytes.slice(1024, 1056), {
        strategy: "unsafe-cast",
      }),
    };

    const signalBytes = Txn.applicationArgs(1);
    const signalsArc4 = convertBytes<arc4.DynamicArray<Uint256>>(signalBytes, {
      strategy: "unsafe-cast",
    });

    const signals: Uint256[] = [];
    for (const s of signalsArc4) {
      signals.push(s);
    }

    const lwBytes = Txn.applicationArgs(3);
    const lwArc4 = convertBytes<
      arc4.Tuple<[arc4.DynamicArray<Uint256>, Uint256, Uint256]>
    >(lwBytes, { strategy: "unsafe-cast" });

    const lw: LagrangeWitness = {
      L: [] as Uint256[],
      xin: lwArc4.at(1),
      zh: lwArc4.at(2),
    };

    for (const v of lwArc4.at(0)) {
      lw.L.push(v);
    }

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

    const vk = decodeVk(vkBytes);

    let challenges = computeChallenges(vk, signals, proof);

    const calc = calculateLagrangeEvaluations(challenges, vk);

    return {
      L: calc.L,
      xin: calc.challenges.xin,
      zh: calc.challenges.zh,
    };
  }
}
