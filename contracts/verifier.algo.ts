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
  clone,
} from "@algorandfoundation/algorand-typescript";
import { EllipticCurve } from "@algorandfoundation/algorand-typescript/op";

/** Fr */
const BLS12_381_SCALAR_MODULUS = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
  ),
);

function frMul(a: bytes<32>, b: bytes<32>): bytes<32> {
  const aBig = BigUint(a);
  const bBig = BigUint(b);
  const result: biguint = (aBig * bBig) % BLS12_381_SCALAR_MODULUS;
  return Bytes(result).toFixed({ length: 32 });
}

function frSub(a: bytes<32>, b: bytes<32>): bytes<32> {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN: biguint = BigUint(a) % r;
  const bN: biguint = BigUint(b) % r;
  const res: biguint = (aN + r - bN) % r; // (a - b) mod r, guaranteed non-negative
  return Bytes(res).toFixed({ length: 32 });
}

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
  xin: bytes<32>;
  zh: bytes<32>;
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

  private getChallenge(td: bytes): bytes<32> {
    let hash = op.keccak256(td);
    return Bytes(BigUint(hash) % BLS12_381_SCALAR_MODULUS).toFixed({
      length: 32,
    });
  }

  computeChallenges(
    vk: VerificationKey,
    signals: PublicSignals,
    proof: Proof,
  ): Challenges {
    /////////////////////////////////////
    // Challenge round 2: beta and gamma
    ////////////////////////////////////
    let td = op.concat(vk.Qm, vk.Ql);
    td = op.concat(td, vk.Qr);
    td = op.concat(td, vk.Qo);
    td = op.concat(td, vk.Qc);
    td = op.concat(td, vk.S1);
    td = op.concat(td, vk.S2);
    td = op.concat(td, vk.S3);

    for (const signal of signals) {
      td = op.concat(td, signal);
    }

    td = op.concat(td, proof.A);
    td = op.concat(td, proof.B);
    td = op.concat(td, proof.C);

    const beta = this.getChallenge(td);

    // gamma
    td = Bytes();
    td = op.concat(td, beta);
    const gamma = this.getChallenge(td);

    ////////////////////////////
    // Challenge round 3: alpha
    ////////////////////////////
    td = Bytes();
    td = op.concat(td, beta);
    td = op.concat(td, gamma);
    td = op.concat(td, proof.Z);
    const alpha = this.getChallenge(td);

    ////////////////////////////
    // Challenge round 4: xi
    ///////////////////////////
    td = Bytes();
    td = op.concat(td, beta);
    td = op.concat(td, proof.T1);
    td = op.concat(td, proof.T2);
    td = op.concat(td, proof.T3);
    const xi = this.getChallenge(td);

    ////////////////////////////
    // Challenge round 5: v
    //////////////////////////
    td = Bytes();
    td = op.concat(td, xi);
    td = op.concat(td, proof.eval_a);
    td = op.concat(td, proof.eval_b);
    td = op.concat(td, proof.eval_c);
    td = op.concat(td, proof.eval_s1);
    td = op.concat(td, proof.eval_s2);
    td = op.concat(td, proof.eval_zw);

    const v = new FixedArray<bytes<32>, 6>();
    v[1] = this.getChallenge(td);

    for (let i: uint64 = 2; i < 6; i++) {
      v[i] = frMul(v[i - 1] as bytes<32>, v[1]);
    }

    ////////////////////////////
    // Challenge: u
    /////////////////////////////
    td = Bytes();
    td = op.concat(td, proof.Wxi);
    td = op.concat(td, proof.Wxiw);
    const u = this.getChallenge(td);

    return {
      beta,
      gamma,
      alpha,
      xi,
      v,
      u,
      xin: Bytes<32>(),
      zh: Bytes<32>(),
    };
  }

  calculateLagrangeEvaluations(
    challengesInput: Challenges,
    vk: VerificationKey,
  ): { L: bytes<32>[]; challenges: Challenges } {
    const challenges = clone(challengesInput);
    let xin = challenges.xi;

    let domainSize: uint64 = 1;
    for (let i: uint64 = 0; i < vk.power; i++) {
      xin = frMul(xin, xin);
      domainSize *= 2;
    }

    challenges.xin = xin;
    challenges.zh = frSub(xin, Bytes<32>());

    const L: bytes<32>[] = [];

    return { L, challenges };
  }
}
