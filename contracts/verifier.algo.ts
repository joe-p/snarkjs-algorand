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

const G1_ONE = Bytes.fromHex(
  "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
);

const G2_ONE = Bytes.fromHex(
  "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
);

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

const R_MINUS_1 = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
  ),
);

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
  k1: uint64;
  k2: uint64;
  X_2: bytes<192>;
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

function g1TimesFr(p: bytes<96>, s: biguint): bytes<96> {
  return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    length: 96,
  });
}

function g1Add(p1: bytes<96>, p2: bytes<96>): bytes<96> {
  return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    length: 96,
  });
}

function g1Neg(p: bytes<96>): bytes<96> {
  return g1TimesFr(p, R_MINUS_1);
}

function g1Sub(p: bytes<96>, q: bytes<96>): bytes<96> {
  return g1Add(p, g1Neg(q));
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

    const d = this.calculateD(proof, challenges, vk, L[1] as Uint256);
    namedLog("D", d);

    const f = this.calculateF(proof, challenges, vk, d);
    namedLog("F", f);

    const e = this.calculateE(proof, challenges, r0);
    namedLog("E", e);

    assert(
      this.isValidPairing(proof, challenges, vk, e, f),
      "Pairing check failed",
    );

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

  private calculateD(
    proof: Proof,
    challenges: Challenges,
    vk: VerificationKey,
    l1: Uint256,
  ): bytes<96> {
    let d1 = g1TimesFr(vk.Qm, frMul(proof.eval_a.native, proof.eval_b.native));
    d1 = g1Add(d1, g1TimesFr(vk.Ql, proof.eval_a.native));
    d1 = g1Add(d1, g1TimesFr(vk.Qr, proof.eval_b.native));
    d1 = g1Add(d1, g1TimesFr(vk.Qo, proof.eval_c.native));
    d1 = g1Add(d1, vk.Qc);

    const betaxi = frMul(challenges.beta.native, challenges.xi.native);

    const d2a1 = frAdd(
      frAdd(proof.eval_a.native, betaxi),
      challenges.gamma.native,
    );
    const d2a2 = frAdd(
      frAdd(proof.eval_b.native, frMul(betaxi, BigUint(vk.k1))),
      challenges.gamma.native,
    );
    const d2a3 = frAdd(
      frAdd(proof.eval_c.native, frMul(betaxi, BigUint(vk.k2))),
      challenges.gamma.native,
    );

    const d2a = frMul(frMul(frMul(d2a1, d2a2), d2a3), challenges.alpha.native);

    const d2b = frMul(
      l1.native,
      frMul(challenges.alpha.native, challenges.alpha.native),
    );

    const d2 = g1TimesFr(proof.Z, frAdd(frAdd(d2a, d2b), challenges.u.native));

    const d3a = frAdd(
      frAdd(
        proof.eval_a.native,
        frMul(challenges.beta.native, proof.eval_s1.native),
      ),
      challenges.gamma.native,
    );
    const d3b = frAdd(
      frAdd(
        proof.eval_b.native,
        frMul(challenges.beta.native, proof.eval_s2.native),
      ),
      challenges.gamma.native,
    );
    const d3c = frMul(
      frMul(challenges.alpha.native, challenges.beta.native),
      proof.eval_zw.native,
    );

    const d3 = g1TimesFr(vk.S3, frMul(frMul(d3a, d3b), d3c));

    const d4low = proof.T1;
    const d4mid = g1TimesFr(proof.T2, challenges.xin.native);
    const d4high = g1TimesFr(
      proof.T3,
      frMul(challenges.xin.native, challenges.xin.native),
    );
    let d4 = g1Add(d4low, g1Add(d4mid, d4high));
    d4 = g1TimesFr(d4, challenges.zh.native);

    const d = g1Sub(g1Sub(g1Add(d1, d2), d3), d4);

    return d;
  }

  private calculateF(
    proof: Proof,
    challenges: Challenges,
    vk: VerificationKey,
    D: bytes<96>,
  ): bytes<96> {
    let res = g1Add(D, g1TimesFr(proof.A, (challenges.v[1] as Uint256).native));
    res = g1Add(res, g1TimesFr(proof.B, (challenges.v[2] as Uint256).native));
    res = g1Add(res, g1TimesFr(proof.C, (challenges.v[3] as Uint256).native));

    res = g1Add(res, g1TimesFr(vk.S1, (challenges.v[4] as Uint256).native));
    res = g1Add(res, g1TimesFr(vk.S2, (challenges.v[5] as Uint256).native));

    return res;
  }

  private calculateE(
    proof: Proof,
    challenges: Challenges,
    r0: Uint256,
  ): bytes<96> {
    let e = frSub(
      frMul((challenges.v[1] as Uint256).native, proof.eval_a.native),
      r0.native,
    );

    e = frAdd(
      e,
      frMul((challenges.v[2] as Uint256).native, proof.eval_b.native),
    );
    e = frAdd(
      e,
      frMul((challenges.v[3] as Uint256).native, proof.eval_c.native),
    );
    e = frAdd(
      e,
      frMul((challenges.v[4] as Uint256).native, proof.eval_s1.native),
    );
    e = frAdd(
      e,
      frMul((challenges.v[5] as Uint256).native, proof.eval_s2.native),
    );
    e = frAdd(e, frMul(challenges.u.native, proof.eval_zw.native));

    const res = g1TimesFr(G1_ONE.toFixed({ length: 96 }), e);

    return res;
  }

  private isValidPairing(
    proof: Proof,
    challenges: Challenges,
    vk: VerificationKey,
    E: bytes<96>,
    F: bytes<96>,
  ): boolean {
    let A1 = proof.Wxi;
    A1 = g1Add(A1, g1TimesFr(proof.Wxiw, challenges.u.native));

    let B1 = g1TimesFr(proof.Wxi, challenges.xi.native);
    const s = frMul(frMul(challenges.u.native, challenges.xi.native), Frw11);
    B1 = g1Add(B1, g1TimesFr(proof.Wxiw, s));
    B1 = g1Add(B1, F);
    B1 = g1Sub(B1, E);

    // const res = await curve.pairingEq(G1.neg(A1), vk.X_2, B1, curve.G2.one);
    const res = op.EllipticCurve.pairingCheck(
      op.Ec.BLS12_381g1,
      op.concat(g1Neg(A1), B1), // G1 points
      op.concat(vk.X_2, G2_ONE), // G2 points
    );

    return res;
  }
}
