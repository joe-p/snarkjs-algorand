import {
  Contract,
  Global,
  LogicSig,
  Txn,
  arc4,
  assert,
  assertMatch,
} from "@algorandfoundation/algorand-typescript";
import {
  abimethod,
  interpretAsArc4,
  Uint256,
} from "@algorandfoundation/algorand-typescript/arc4";
import {
  verifyFromTemplateWithLogs,
  type VerificationKey,
  type PublicSignals,
  type Proof,
  verifyFromTemplate,
} from "./plonk_bls12381.algo";

export class PlonkVerifierWithLogs extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: VerificationKey): void {}

  verify(signals: PublicSignals, proof: Proof): void {
    assert(verifyFromTemplateWithLogs(signals, proof), "Verification failed");
  }
}

export class PlonkVerifier extends Contract {
  /** Dummy function that only exists so we can have the VerificationKey type in the generated client */
  @abimethod({ allowActions: "CloseOut" })
  public _dummy(_vk: VerificationKey): void {}

  verify(signals: PublicSignals, proof: Proof): void {
    assert(verifyFromTemplateWithLogs(signals, proof), "Verification failed");
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
      eval_a: interpretAsArc4<Uint256>(proofBytes.slice(864, 896)),
      eval_b: interpretAsArc4<Uint256>(proofBytes.slice(896, 928)),
      eval_c: interpretAsArc4<Uint256>(proofBytes.slice(928, 960)),
      eval_s1: interpretAsArc4<Uint256>(proofBytes.slice(960, 992)),
      eval_s2: interpretAsArc4<Uint256>(proofBytes.slice(992, 1024)),
      eval_zw: interpretAsArc4<Uint256>(proofBytes.slice(1024, 1056)),
    };

    const signalBytes = Txn.applicationArgs(1);
    const signalsArc4 =
      interpretAsArc4<arc4.DynamicArray<Uint256>>(signalBytes);

    const signals: Uint256[] = [];

    for (const s of signalsArc4) {
      signals.push(s);
    }

    assert(verifyFromTemplate(signals, proof), "Verification failed");

    return true;
  }
}

export class SignalsAndProof extends Contract {
  public signalsAndProof(signals: Uint256[], proof: Proof): void {}
}
