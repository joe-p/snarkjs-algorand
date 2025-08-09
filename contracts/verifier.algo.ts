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
import { Uint, Uint256 } from "@algorandfoundation/algorand-typescript/arc4";
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

function frAdd(a: biguint, b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN: biguint = a % r;
  const bN: biguint = b % r;
  return (aN + bN) % r;
}

function frScalar(a: biguint): biguint {
  return a % BLS12_381_SCALAR_MODULUS;
}

function b32(a: biguint): bytes<32> {
  return new Uint256(a).bytes.toFixed({ length: 32 });
}

export type PublicSignals = Uint256[];

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
  eval_a: Uint256;
  eval_b: Uint256;
  eval_c: Uint256;
  eval_s1: Uint256;
  eval_s2: Uint256;
  eval_zw: Uint256;
};

export type Challenges = {
  beta: Uint256;
  gamma: Uint256;
  alpha: Uint256;
  xi: Uint256;
  v: FixedArray<Uint256, 6>;
  u: Uint256;
  xin: Uint256;
  zh: Uint256;
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
    let challenges = this.computeChallenges(vk, signals, proof);
    namedLog("beta", challenges.beta.bytes);
    namedLog("gamma", challenges.gamma.bytes);
    namedLog("alpha", challenges.alpha.bytes);
    namedLog("xi", challenges.xi.bytes);
    namedLog("u", challenges.u.bytes);
    namedLog("xin", challenges.xin.bytes);
    namedLog("zh", challenges.zh.bytes);
    namedLog("v[1]", (challenges.v[1] as Uint256).bytes);
    namedLog("v[2]", (challenges.v[2] as Uint256).bytes);
    namedLog("v[3]", (challenges.v[3] as Uint256).bytes);
    namedLog("v[4]", (challenges.v[4] as Uint256).bytes);
    namedLog("v[5]", (challenges.v[5] as Uint256).bytes);

    const { L, challenges: updatedChallenges } =
      this.calculateLagrangeEvaluations(challenges, vk);

    namedLog("L1(xi)", (L[1] as Uint256).bytes);

    challenges = clone(updatedChallenges);

    const pi = this.calculatePI(signals, L);
    namedLog("PI(xi)", pi.bytes);

    const r0 = this.calculateR0(proof, challenges, pi, L[1] as Uint256);
    namedLog("r0", r0.bytes);

    return true;
  }

  private getChallenge(td: bytes): Uint256 {
    let hash = op.keccak256(td);
    return new Uint256(frScalar(BigUint(hash)));
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

    for (const signal of signals) {
      td = op.concat(td, b32(frScalar(signal.native)));
    }

    td = op.concat(td, proof.A);
    td = op.concat(td, proof.B);
    td = op.concat(td, proof.C);

    const beta = this.getChallenge(td);

    // gamma
    td = Bytes();
    td = op.concat(td, beta.bytes);
    const gamma = this.getChallenge(td);

    ////////////////////////////
    // Challenge round 3: alpha
    ////////////////////////////
    td = Bytes();
    td = op.concat(td, beta.bytes);
    td = op.concat(td, gamma.bytes);
    td = op.concat(td, proof.Z);
    const alpha = this.getChallenge(td);

    ////////////////////////////
    // Challenge round 4: xi
    ///////////////////////////
    td = Bytes();
    td = op.concat(td, alpha.bytes);
    td = op.concat(td, proof.T1);
    td = op.concat(td, proof.T2);
    td = op.concat(td, proof.T3);
    const xi = this.getChallenge(td);

    ////////////////////////////
    // Challenge round 5: v
    //////////////////////////
    td = Bytes();
    td = op.concat(td, xi.bytes);
    td = op.concat(td, proof.eval_a.bytes);
    td = op.concat(td, proof.eval_b.bytes);
    td = op.concat(td, proof.eval_c.bytes);
    td = op.concat(td, proof.eval_s1.bytes);
    td = op.concat(td, proof.eval_s2.bytes);
    td = op.concat(td, proof.eval_zw.bytes);

    const v = new FixedArray<Uint256, 6>();
    v[1] = this.getChallenge(td);

    for (let i: uint64 = 2; i < 6; i++) {
      v[i] = new Uint256(frMul((v[i - 1] as Uint256).native, v[1].native));
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
      xin: new Uint256(),
      zh: new Uint256(),
    };
  }

  private calculateLagrangeEvaluations(
    challengesInput: Challenges,
    vk: VerificationKey,
  ): { L: Uint256[]; challenges: Challenges } {
    const challenges = clone(challengesInput);
    let xin = challenges.xi.native;

    let domainSize: uint64 = 1;
    for (let i: uint64 = 0; i < vk.power; i++) {
      xin = frMul(xin, xin);
      domainSize *= 2;
    }

    challenges.xin = new Uint256(xin);
    challenges.zh = new Uint256(frSub(xin, BigUint(1)));

    const n = frScalar(BigUint(domainSize));

    let w = BigUint(1);

    const L: Uint256[] = [new Uint256(), new Uint256()];
    const iterations: uint64 = vk.nPublic === 0 ? 1 : vk.nPublic;
    for (let i: uint64 = 1; i <= iterations; i++) {
      L[i] = new Uint256(
        frDiv(
          frMul(w, challenges.zh.native),
          frMul(n, frSub(challenges.xi.native, w)),
        ),
      );

      w = frMul(w, Frw11);
    }
    return { L, challenges };
  }

  private calculatePI(publicSignals: PublicSignals, L: Uint256[]): Uint256 {
    let pi = BigUint(0);
    for (let i: uint64 = 0; i < publicSignals.length; i++) {
      const w = frScalar((publicSignals[i] as Uint256).native);
      pi = frSub(pi, frMul(w, (L[i + 1] as Uint256).native));
    }
    return new Uint256(pi);
  }

  private calculateR0(
    proof: Proof,
    challenges: Challenges,
    pi: Uint256,
    l1: Uint256,
  ): Uint256 {
    const e1 = pi.native;

    const e2 = frMul(
      l1.native,
      frMul(challenges.alpha.native, challenges.alpha.native),
    );

    let e3a = frAdd(
      proof.eval_a.native,
      frMul(challenges.beta.native, proof.eval_s1.native),
    );

    e3a = frAdd(e3a, challenges.gamma.native);

    let e3b = frAdd(
      proof.eval_b.native,
      frMul(challenges.beta.native, proof.eval_s2.native),
    );
    e3b = frAdd(e3b, challenges.gamma.native);

    let e3c = frAdd(proof.eval_c.native, challenges.gamma.native);

    let e3 = frMul(frMul(e3a, e3b), e3c);
    e3 = frMul(e3, proof.eval_zw.native);
    e3 = frMul(e3, challenges.alpha.native);

    const r0 = frSub(frSub(e1, e2), e3);

    return new Uint256(r0);
  }
}
