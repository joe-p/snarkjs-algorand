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
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";
import { keccak256 } from "@algorandfoundation/algorand-typescript/op";

/** Fr.w[11] precomputed by scripts/frw.ts */
const Frw11 = BigUint(
  Bytes.fromHex(
    "43527a8bca252472eb674a1a620890d7a534af14b61e0abe74a1f6718c130477",
  ),
);

/** Fr */
const BLS12_381_SCALAR_MODULUS = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
  ),
);

function frMul(a: biguint, b: biguint): biguint {
  return (a * b) % BLS12_381_SCALAR_MODULUS;
}

const BLS12_381_R_MINUS_2 = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffeffffffff",
  ),
);

function modPow(base: biguint, exp: biguint, mod: biguint): biguint {
  let result = 1n as biguint;
  let b: biguint = base % mod;
  let e: biguint = exp;
  while (e > (0n as biguint)) {
    if ((e & (1n as biguint)) !== (0n as biguint)) {
      result = (result * b) % mod;
    }
    b = (b * b) % mod;
    e = e / BigUint(2); // e >> 1
  }
  return result;
}

function frInv(b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const x = frScalar(BigUint(b));
  assert(x !== (0n as biguint), "Fr inverse of zero");
  const inv = modPow(x, BLS12_381_R_MINUS_2, r);
  return inv;
}

function frDiv(a: biguint, b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN = frScalar(BigUint(a));
  const bInv = BigUint(frInv(b)); // already reduced & padded
  return (aN * bInv) % r;
}

function frSub(a: biguint, b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN: biguint = a % r;
  const bN: biguint = b % r;
  return (aN + r - bN) % r; // (a - b) mod r, guaranteed non-negative
}

function frScalar(a: biguint): biguint {
  return a % BLS12_381_SCALAR_MODULUS;
}

function b32(a: biguint): bytes<32> {
  return new Uint256(a).bytes.toFixed({ length: 32 });
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

function namedLog(name: string, value: bytes): void {
  log(name);
  log(value);
}

export class PlonkVerifier extends Contract {
  public verify(
    vk: VerificationKey,
    signals: PublicSignals,
    proof: Proof,
  ): boolean {
    // Implementation of the verification logic
    const challenge = this.computeChallenges(vk, signals, proof);
    namedLog("beta", challenge.beta);
    return true;
  }

  private getChallenge(td: bytes): bytes<32> {
    let hash = op.keccak256(td);
    return b32(frScalar(BigUint(hash)));
  }

  private computeChallenges(
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

    namedLog("getChallenge 7", keccak256(td));
    for (const signal of signals) {
      td = op.concat(td, b32(frScalar(BigUint(signal))));
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
      v[i] = b32(frMul(BigUint(v[i - 1] as bytes<32>), BigUint(v[1])));
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

  private calculateLagrangeEvaluations(
    challengesInput: Challenges,
    vk: VerificationKey,
  ): { L: bytes<32>[]; challenges: Challenges } {
    const challenges = clone(challengesInput);
    let xin = BigUint(challenges.xi);

    let domainSize: uint64 = 1;
    for (let i: uint64 = 0; i < vk.power; i++) {
      xin = frMul(xin, xin);
      domainSize *= 2;
    }

    challenges.xin = b32(xin);
    challenges.zh = b32(frSub(xin, BigUint(1)));

    const L: bytes<32>[] = [];

    const n = frScalar(BigUint(domainSize));

    let w = BigUint(1);

    const iterations: uint64 = vk.nPublic === 0 ? 1 : vk.nPublic;
    for (let i: uint64 = 1; i < iterations; i++) {
      L[i] = b32(
        frDiv(
          frMul(w, BigUint(challenges.zh)),
          frMul(n, frSub(BigUint(challenges.xi), w)),
        ),
      );

      w = frMul(w, Frw11);
    }
    return { L, challenges };
  }
}
