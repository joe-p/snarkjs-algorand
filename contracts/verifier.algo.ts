import {
  Contract,
  type bytes,
  op,
  BigUint,
  FixedArray,
  type uint64,
  Bytes,
  type biguint,
  assert,
  log,
} from "@algorandfoundation/algorand-typescript";

export type PublicSignals = bytes<32>[];

export type VerificationKey = {
  Qm: bytes<96>;
  Ql: bytes<96>;
  Qr: bytes<96>;
  Qo: bytes<96>;
  Qc: bytes<96>;
  S1: bytes<96>;
  S2: bytes<96>;
  S3: bytes<96>;
  power: uint64; // Domain size = 2^power
  nPublic: uint64; // Number of public inputs
  omega: bytes<32>; // Primitive root of unity
};

export type Proof = {
  // Uncompressed G1 points
  A: bytes<96>;
  B: bytes<96>;
  C: bytes<96>;
  Z: bytes<96>;
  T1: bytes<96>;
  T2: bytes<96>;
  T3: bytes<96>;
  Wxi: bytes<96>;
  Wxiw: bytes<96>;
  // Field evaluations are 32 bytes (SnarkJS internal representation)
  eval_a: bytes<32>;
  eval_b: bytes<32>;
  eval_c: bytes<32>;
  eval_s1: bytes<32>;
  eval_s2: bytes<32>;
  eval_zw: bytes<32>;
};

export type Challenges = {
  beta: bytes<32>;
  gamma: bytes<32>;
  alpha: bytes<32>;
  xi: bytes<32>;
  v: FixedArray<bytes<32>, 6>;
  u: bytes<32>;
};

export type LagrangeEvaluations = {
  xin: bytes<32>; // xi^(2^power)
  zh: bytes<32>; // xin - 1
  L: bytes<32>[]; // L[1] through L[nPublic]
};

export class PlonkVerifier extends Contract {
  public verify(
    vk: VerificationKey,
    signals: PublicSignals,
    proof: Proof,
  ): boolean {
    // Implementation of the verification logic
    const challenge = this.computeChallenges(vk, signals, proof);
    log(challenge.alpha);
    return true;
  }

  computeChallenges(
    vk: VerificationKey,
    signals: PublicSignals,
    proof: Proof,
  ): Challenges {
    const BLS12_381_SCALAR_MODULUS = BigUint(
      Bytes.fromHex(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
      ),
    );

    // transcript.addPolCommitment() for each VK commitment
    let td = op.concat(vk.Qm, vk.Ql);
    td = op.concat(td, vk.Qr);
    td = op.concat(td, vk.Qo);
    td = op.concat(td, vk.Qc);
    td = op.concat(td, vk.S1);
    td = op.concat(td, vk.S2);
    td = op.concat(td, vk.S3);

    // transcript.addScalar() for each public signal
    for (const signal of signals) {
      td = op.concat(td, signal);
    }

    // transcript.addPolCommitment() for wire commitments
    td = op.concat(td, proof.A);
    td = op.concat(td, proof.B);
    td = op.concat(td, proof.C);

    let hash = op.keccak256(td);
    const beta: biguint = BigUint(hash) % BLS12_381_SCALAR_MODULUS;

    return {
      beta: Bytes<32>(beta),
      // TODO: Implement the rest of the challenge rounds
      alpha: Bytes<32>(beta),
      gamma: Bytes<32>(beta),
      xi: Bytes<32>(beta),
      u: Bytes<32>(beta),
      v: new FixedArray<bytes<32>, 6>(
        Bytes<32>(beta),
        Bytes<32>(beta),
        Bytes<32>(beta),
        Bytes<32>(beta),
        Bytes<32>(beta),
        Bytes<32>(beta),
      ),
    };
  }
}
