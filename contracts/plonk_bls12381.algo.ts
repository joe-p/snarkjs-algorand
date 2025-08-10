import {
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
  TemplateVar,
} from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

/**
 * PLONK verifier for BLS12-381 (SNARKJS-compatible)
 *
 * This verifier mirrors SNARKJS’s transcript layout and linearization:
 * 1) Derive Fiat–Shamir challenges from a *chained* transcript (each round hashes
 *    the previous challenge(s) and new material, not the entire history).
 * 2) Evaluate Lagrange basis terms for public inputs and the L₁(ξ) boundary term.
 * 3) Build the linearization commitment D (gates + permutation constraints + quotient parts).
 * 4) Batch openings via powers of a single random challenge v.
 * 5) Single pairing check with (Wξ, Wξω) openings.
 *
 * Field operations are over BLS12-381 Fr; commitments are on G1; the SRS element [x]₂ is on G2.
 */

/**
 * Generator point for BLS12-381 G1 group (uncompressed format, big-endian)
 * 96 bytes = x(48) || y(48)
 */
const G1_ONE = Bytes.fromHex(
  "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
);

/**
 * Generator point for BLS12-381 G2 group (uncompressed format, big-endian)
 * 192 bytes = x.c0(48) || x.c1(48) || y.c0(48) || y.c1(48)
 */
const G2_ONE = Bytes.fromHex(
  "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
);

/**
 * Primitive 2^11-th root of unity in the BLS12-381 scalar field Fr.
 * This is ω where ω^(2^11) = 1 and ω^k ≠ 1 for 0 < k < 2^11.
 * Used for domain evaluation in circuits with n = 2048 = 2^11 constraints.
 * For circuits with different sizes, a different root of unity would be needed.
 *
 * The plan is to make this a template variable, but trying to do so right now
 * leads to a compiler error during bytecblock construction.
 */
const ROOT_OF_UNITY = BigUint(
  Bytes.fromHex(
    "43527a8bca252472eb674a1a620890d7a534af14b61e0abe74a1f6718c130477",
  ),
);

/** BLS12-381 scalar field modulus (Fr), 32-byte big-endian */
const BLS12_381_SCALAR_MODULUS = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
  ),
);

/**
 * Multiplication in the scalar field Fr.
 * Computes (a * b) mod r where r is the BLS12-381 scalar field modulus.
 * Returns the canonical representative in [0, r-1].
 */
function frMul(a: biguint, b: biguint): biguint {
  return (a * b) % BLS12_381_SCALAR_MODULUS;
}

/**
 * BLS12_381_SCALAR_MODULUS - 1, used for point negation
 */
const R_MINUS_1 = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
  ),
);

/**
 * BLS12_381_SCALAR_MODULUS - 2, used for modular inverse via Fermat's little theorem
 */
const BLS12_381_R_MINUS_2 = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffeffffffff",
  ),
);

/**
 * Fast modular exponentiation using binary square-and-multiply.
 * Computes base^exp mod mod efficiently in O(log exp) time.
 */
function modPow(base: biguint, exp: biguint, mod: biguint): biguint {
  let result = 1n as biguint;
  let b: biguint = base % mod;
  let e: biguint = exp;
  while (e > (0n as biguint)) {
    if ((e & (1n as biguint)) !== (0n as biguint)) {
      result = (result * b) % mod;
    }
    b = (b * b) % mod;
    e = e / BigUint(2);
  }
  return result;
}

/**
 * Modular inverse in the scalar field Fr using Fermat's little theorem.
 * For prime p, computes a^(p-2) mod p = a^(-1) mod p.
 * Requires a ≠ 0 in Fr (enforced by assertion).
 */
function frInv(b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const x = frScalar(BigUint(b));
  assert(x !== (0n as biguint), "Fr inverse of zero");
  const inv = modPow(x, BLS12_381_R_MINUS_2, r);
  return inv;
}

/**
 * Division in the scalar field Fr.
 * Computes a / b = a * b^(-1) mod r where r is the BLS12-381 scalar field modulus.
 * Requires b ≠ 0 (enforced by frInv).
 */
function frDiv(a: biguint, b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN = frScalar(BigUint(a));
  const bInv = BigUint(frInv(b));
  return (aN * bInv) % r;
}

/**
 * Subtraction in the scalar field Fr.
 * Computes (a - b) mod r where r is the BLS12-381 scalar field modulus.
 * Uses (a + r - b) mod r to handle negative results correctly.
 */
function frSub(a: biguint, b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN: biguint = a % r;
  const bN: biguint = b % r;
  return (aN + r - bN) % r;
}

/**
 * Addition in the scalar field Fr.
 * Computes (a + b) mod r where r is the BLS12-381 scalar field modulus.
 * Returns the canonical representative in [0, r-1].
 */
function frAdd(a: biguint, b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN: biguint = a % r;
  const bN: biguint = b % r;
  return (aN + bN) % r;
}

/**
 * Reduce to canonical form in the scalar field Fr.
 * Computes a mod r where r is the BLS12-381 scalar field modulus.
 * Ensures the result is in the range [0, r-1].
 */
function frScalar(a: biguint): biguint {
  return a % BLS12_381_SCALAR_MODULUS;
}

/**
 * Convert a big unsigned integer to 32-byte big-endian representation.
 * Used for serializing field elements in the Fiat-Shamir transcript.
 */
function b32(a: biguint): bytes<32> {
  return new Uint256(a).bytes.toFixed({ length: 32 });
}

export type PublicSignals = Uint256[];

/**
 * PLONK proof structure: G1 points (96B BE) and field evals (32B BE)
 */
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
  // Field evaluations are 32 bytes (SNARKJS internal representation, BE)
  eval_a: Uint256;
  eval_b: Uint256;
  eval_c: Uint256;
  eval_s1: Uint256;
  eval_s2: Uint256;
  eval_zw: Uint256;
};

/**
 * Fiat–Shamir challenges (SNARKJS chaining)
 */
export type Challenges = {
  beta: Uint256;
  gamma: Uint256;
  alpha: Uint256;
  xi: Uint256;
  /** v[i] = v1^i for batching */
  v: FixedArray<Uint256, 6>;
  u: Uint256;
  xin: Uint256;
  zh: Uint256;
};

/**
 * Debug logging helper
 */
function namedLog(name: string, value: bytes): void {
  log(name);
  log(value);
}

/**
 * Scalar multiplication on the BLS12-381 G1 group.
 * Computes s * P where P is a G1 point and s is a scalar in Fr.
 * Returns the result as a 96-byte uncompressed G1 point.
 */
function g1TimesFr(p: bytes<96>, s: biguint): bytes<96> {
  return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    length: 96,
  });
}

/**
 * Point addition on the BLS12-381 G1 group.
 * Computes P1 + P2 where P1 and P2 are G1 points.
 * Returns the result as a 96-byte uncompressed G1 point.
 */
function g1Add(p1: bytes<96>, p2: bytes<96>): bytes<96> {
  return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    length: 96,
  });
}

/**
 * Point negation on the BLS12-381 G1 group.
 * Computes -P where P is a G1 point by multiplying by (r-1) where r is the scalar field modulus.
 * This is equivalent to negating the y-coordinate in affine representation.
 */
function g1Neg(p: bytes<96>): bytes<96> {
  return g1TimesFr(p, R_MINUS_1);
}

/**
 * Point subtraction on the BLS12-381 G1 group.
 * Computes P - Q = P + (-Q) where P and Q are G1 points.
 * Returns the result as a 96-byte uncompressed G1 point.
 */
function g1Sub(p: bytes<96>, q: bytes<96>): bytes<96> {
  return g1Add(p, g1Neg(q));
}

/**
 * PLONK verification key structure with big-endian encodings.
 * Contains all the preprocessed circuit information needed for verification.
 */
export type VerificationKey = {
  /** Multiplication gate selector polynomial commitment [Qm(x)]_1 */
  Qm: bytes<96>;
  /** Left wire selector polynomial commitment [Ql(x)]_1 */
  Ql: bytes<96>;
  /** Right wire selector polynomial commitment [Qr(x)]_1 */
  Qr: bytes<96>;
  /** Output wire selector polynomial commitment [Qo(x)]_1 */
  Qo: bytes<96>;
  /** Constant selector polynomial commitment [Qc(x)]_1 */
  Qc: bytes<96>;
  /** First permutation polynomial commitment [S_σ(1)(x)]_1 */
  S1: bytes<96>;
  /** Second permutation polynomial commitment [S_σ(2)(x)]_1 */
  S2: bytes<96>;
  /** Third permutation polynomial commitment [S_σ(3)(x)]_1 */
  S3: bytes<96>;
  /** Circuit size as power of 2 (i.e., n = 2^power) */
  power: uint64;
  /** Number of public inputs to the circuit */
  nPublic: uint64;
  /** First permutation coset generator (multiplicative offset for wire 2) */
  k1: uint64;
  /** Second permutation coset generator (multiplicative offset for wire 3) */
  k2: uint64;
  /** SRS element [x]_2 in G2 for pairing check, uncompressed BE */
  X_2: bytes<192>;
};

/**
 * Verify proof using verification key from template variable
 */
export function verifyFromTemplate(
  signals: PublicSignals,
  proof: Proof,
): boolean {
  const vkBytes = TemplateVar<bytes>("VERIFICATION_KEY");

  // Serialized VK layout (BE):
  // Qm||Ql||Qr||Qo||Qc||S1||S2||S3||power||nPublic||k1||k2||X_2
  const vk: VerificationKey = {
    Qm: vkBytes.slice(0, 96).toFixed({ length: 96 }),
    Ql: vkBytes.slice(96, 192).toFixed({ length: 96 }),
    Qr: vkBytes.slice(192, 288).toFixed({ length: 96 }),
    Qo: vkBytes.slice(288, 384).toFixed({ length: 96 }),
    Qc: vkBytes.slice(384, 480).toFixed({ length: 96 }),
    S1: vkBytes.slice(480, 576).toFixed({ length: 96 }),
    S2: vkBytes.slice(576, 672).toFixed({ length: 96 }),
    S3: vkBytes.slice(672, 768).toFixed({ length: 96 }),
    power: op.btoi(vkBytes.slice(768, 776)),
    nPublic: op.btoi(vkBytes.slice(776, 784)),
    k1: op.btoi(vkBytes.slice(784, 792)),
    k2: op.btoi(vkBytes.slice(792, 800)),
    X_2: vkBytes.slice(800, 992).toFixed({ length: 192 }),
  };

  return verify(vk, signals, proof);
}

/**
 * Main PLONK verification function
 */
export function verify(
  vk: VerificationKey,
  signals: PublicSignals,
  proof: Proof,
): boolean {
  // 1) Fiat–Shamir challenges from transcript (SNARKJS chaining)
  let challenges = computeChallenges(vk, signals, proof);
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

  // 2) Lagrange evaluations used by PI(ξ) and L1(ξ)
  const { L, challenges: updatedChallenges } = calculateLagrangeEvaluations(
    challenges,
    vk,
  );
  namedLog("L1(xi)", (L[1] as Uint256).bytes);
  challenges = clone(updatedChallenges);

  // 3) Public input polynomial at ξ
  const pi = calculatePI(signals, L);
  namedLog("PI(xi)", pi.bytes);

  // 4) Linearization polynomial constant term r0
  const r0 = calculateR0(proof, challenges, pi, L[1] as Uint256);
  namedLog("r0", r0.bytes);

  // 5) Linearization commitment D and batch opening commitment F (optimized)
  const { D: d, F: f } = calculateDF(proof, challenges, vk, L[1] as Uint256);
  namedLog("D", d);
  namedLog("F", f);

  // 7) Batched evaluation commitment E (on [1]_1)
  const e = calculateE(proof, challenges, r0);
  namedLog("E", e);

  // 8) Final pairing check
  return isValidPairing(proof, challenges, vk, e, f);
}

/**
 * Derive a challenge by hashing the current transcript chunk, reduced to Fr
 */
export function getChallenge(td: bytes): Uint256 {
  let hash = op.keccak256(td);
  return new Uint256(frScalar(BigUint(hash)));
}

/**
 * Compute all Fiat–Shamir challenges following SNARKJS transcript chaining
 */
export function computeChallenges(
  vk: VerificationKey,
  signals: PublicSignals,
  proof: Proof,
): Challenges {
  /////////////////////////////////////
  // Challenge round 2: beta and gamma
  /////////////////////////////////////
  // Build transcript with verification key commitments and public inputs
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

  // Add round 1 commitments
  td = op.concat(td, proof.A);
  td = op.concat(td, proof.B);
  td = op.concat(td, proof.C);

  const beta = getChallenge(td);

  // gamma challenge (chaining): gamma = H(beta)
  td = Bytes();
  td = op.concat(td, beta.bytes);
  const gamma = getChallenge(td);

  ////////////////////////////
  // Challenge round 3: alpha
  ////////////////////////////
  td = Bytes();
  td = op.concat(td, beta.bytes);
  td = op.concat(td, gamma.bytes);
  td = op.concat(td, proof.Z);
  const alpha = getChallenge(td);

  ////////////////////////////
  // Challenge round 4: xi
  ///////////////////////////
  td = Bytes();
  td = op.concat(td, alpha.bytes);
  td = op.concat(td, proof.T1);
  td = op.concat(td, proof.T2);
  td = op.concat(td, proof.T3);
  const xi = getChallenge(td);

  ////////////////////////////
  // Challenge round 5: v (powers of v1)
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
  v[1] = getChallenge(td); // v1
  for (let i: uint64 = 2; i < 6; i++) {
    v[i] = new Uint256(frMul((v[i - 1] as Uint256).native, v[1].native)); // v[i] = v1^i
  }

  ////////////////////////////
  // Challenge: u
  /////////////////////////////
  td = Bytes();
  td = op.concat(td, proof.Wxi);
  td = op.concat(td, proof.Wxiw);
  const u = getChallenge(td);

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

/**
 * Evaluate Lagrange terms used by PI and boundary
 */
export function calculateLagrangeEvaluations(
  challengesInput: Challenges,
  vk: VerificationKey,
): { L: Uint256[]; challenges: Challenges } {
  const challenges = clone(challengesInput);
  let xin = challenges.xi.native;

  // Compute xi^n where n = 2^power (domain size)
  let domainSize: uint64 = 1;
  for (let i: uint64 = 0; i < vk.power; i++) {
    xin = frMul(xin, xin);
    domainSize *= 2;
  }

  challenges.xin = new Uint256(xin);
  challenges.zh = new Uint256(frSub(xin, BigUint(1))); // Vanishing polynomial Z_H(ξ) = ξ^n - 1

  const n = frScalar(BigUint(domainSize));

  // Root-of-unity stepping: starts at ω^0 = 1, then steps through ω^1, ω^2, ...
  // The constant Frw11 is specifically for power=11 (n=2048) circuits.
  // IMPORTANT: For circuits with different domain sizes, this verifier would need
  // the appropriate primitive root of unity for that domain size.
  let w = BigUint(1);

  /*
   * Lagrange basis polynomials (SNARKJS form used here):
   *   With w enumerating ω^0, ω^1, ... , we use
   *     L[i] = ( w * Z_H(ξ) ) / ( n * ( ξ - w ) )
   * This matches how the terms are consumed in this verifier.
   * Assumes ξ ≠ w and Z_H(ξ) ≠ 0 for valid proofs.
   */
  const L: Uint256[] = [new Uint256(), new Uint256()];
  // When there are no public inputs (nPublic = 0), we still need L1(ξ) for the boundary constraint
  // that enforces Z(1) = 1 in the permutation argument
  const iterations: uint64 = vk.nPublic === 0 ? 1 : vk.nPublic;
  for (let i: uint64 = 1; i <= iterations; i++) {
    L[i] = new Uint256(
      frDiv(
        frMul(w, challenges.zh.native),
        frMul(n, frSub(challenges.xi.native, w)),
      ),
    );
    w = frMul(w, ROOT_OF_UNITY); // Next root of unity step (ω^i)
  }
  return { L, challenges };
}

/**
 * Public input polynomial evaluation: PI(ξ) = -∑ public[i] * L[i]
 */
export function calculatePI(
  publicSignals: PublicSignals,
  L: Uint256[],
): Uint256 {
  let pi = BigUint(0);
  for (let i: uint64 = 0; i < publicSignals.length; i++) {
    const w = frScalar((publicSignals[i] as Uint256).native);
    pi = frSub(pi, frMul(w, (L[i + 1] as Uint256).native));
  }
  return new Uint256(pi);
}

/**
 * Calculate linearization polynomial constant term r0.
 *
 * r0 is the constant term when evaluating the PLONK relation at ξ, folded as:
 *   r0 = PI(ξ) - L1(ξ)*α² - α*Z(ξ·ω)*(a+β*s1+γ)(b+β*s2+γ)(c+γ)
 */
export function calculateR0(
  proof: Proof,
  challenges: Challenges,
  pi: Uint256,
  l1: Uint256,
): Uint256 {
  // e1: Public input polynomial evaluation PI(ξ)
  const e1 = pi.native;

  // e2: Boundary constraint L1(ξ) * α² (enforces Z(1) = 1)
  const e2 = frMul(
    l1.native,
    frMul(challenges.alpha.native, challenges.alpha.native),
  );

  // e3: Permutation check contribution (numerator part)
  // α * Z(ξ·ω) * [(a + β*s1 + γ)(b + β*s2 + γ)(c + γ)]
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

  // r0 = e1 - e2 - e3
  const r0 = frSub(frSub(e1, e2), e3);
  return new Uint256(r0);
}

/**
 * Calculate linearization polynomial commitment D and batch opening commitment F
 * with optimized multi-scalar operations.
 *
 * D = d1 + d2 - d3 - d4, where:
 * - d1: Gate constraints Qm*a*b + Ql*a + Qr*b + Qo*c + Qc
 * - d2: Permutation argument numerator folded into Z
 * - d3: Permutation argument denominator folded into S3
 * - d4: Quotient reconstruction T(ξ) * Z_H(ξ), where T(ξ)=T1 + ξ^n*T2 + ξ^{2n}*T3
 *
 * F = D + v1*A + v2*B + v3*C + v4*S1 + v5*S2, with v[i] = v1^i
 */
export function calculateDF(
  proof: Proof,
  challenges: Challenges,
  vk: VerificationKey,
  l1: Uint256,
): { D: bytes<96>; F: bytes<96> } {
  // Combine gate constraints and quotient terms in single multi-scalar operation
  // Points: [Qm, Ql, Qr, Qo, T1, T2, T3]
  let dPoints = op.concat(vk.Qm, vk.Ql);
  dPoints = op.concat(dPoints, vk.Qr);
  dPoints = op.concat(dPoints, vk.Qo);
  dPoints = op.concat(dPoints, proof.T1);
  dPoints = op.concat(dPoints, proof.T2);
  dPoints = op.concat(dPoints, proof.T3);

  // Gate constraint scalars
  const gateScalar1 = frMul(proof.eval_a.native, proof.eval_b.native); // Qm coefficient
  const gateScalar2 = proof.eval_a.native; // Ql coefficient
  const gateScalar3 = proof.eval_b.native; // Qr coefficient
  const gateScalar4 = proof.eval_c.native; // Qo coefficient
  
  // Quotient scalars (negated for subtraction: -T(ξ) * Z_H(ξ))
  const quotientScalar1 = frSub(BigUint(0), frMul(BigUint(1), challenges.zh.native)); // -T1*zh
  const quotientScalar2 = frSub(BigUint(0), frMul(challenges.xin.native, challenges.zh.native)); // -T2*xin*zh
  const quotientScalar3 = frSub(BigUint(0), frMul(frMul(challenges.xin.native, challenges.xin.native), challenges.zh.native)); // -T3*xin²*zh

  // Scalars: [gate scalars, quotient scalars]
  let dScalars = op.concat(b32(gateScalar1), b32(gateScalar2));
  dScalars = op.concat(dScalars, b32(gateScalar3));
  dScalars = op.concat(dScalars, b32(gateScalar4));
  dScalars = op.concat(dScalars, b32(quotientScalar1));
  dScalars = op.concat(dScalars, b32(quotientScalar2));
  dScalars = op.concat(dScalars, b32(quotientScalar3));

  // Single multi-scalar operation for D components
  const dBatched = op.EllipticCurve.scalarMulMulti(op.Ec.BLS12_381g1, dPoints, dScalars);
  let D = g1Add(dBatched.toFixed({ length: 96 }), vk.Qc); // Add Qc constant term
  
  // Add Z component to D (complex scalar calculation)
  const betaxi = frMul(challenges.beta.native, challenges.xi.native);
  const d2a1 = frAdd(frAdd(proof.eval_a.native, betaxi), challenges.gamma.native);
  const d2a2 = frAdd(frAdd(proof.eval_b.native, frMul(betaxi, BigUint(vk.k1))), challenges.gamma.native);
  const d2a3 = frAdd(frAdd(proof.eval_c.native, frMul(betaxi, BigUint(vk.k2))), challenges.gamma.native);
  const d2a = frMul(frMul(frMul(d2a1, d2a2), d2a3), challenges.alpha.native);
  const d2b = frMul(l1.native, frMul(challenges.alpha.native, challenges.alpha.native));
  const zScalar = frAdd(frAdd(d2a, d2b), challenges.u.native);
  
  D = g1Add(D, g1TimesFr(proof.Z, zScalar));
  
  // Subtract S3 component from D (permutation denominator)
  const d3a = frAdd(frAdd(proof.eval_a.native, frMul(challenges.beta.native, proof.eval_s1.native)), challenges.gamma.native);
  const d3b = frAdd(frAdd(proof.eval_b.native, frMul(challenges.beta.native, proof.eval_s2.native)), challenges.gamma.native);
  const d3c = frMul(frMul(challenges.alpha.native, challenges.beta.native), proof.eval_zw.native);
  const s3Scalar = frMul(frMul(d3a, d3b), d3c);
  
  D = g1Sub(D, g1TimesFr(vk.S3, s3Scalar));
  
  // Calculate F = D + v*[A,B,C,S1,S2] using single multi-scalar operation
  // Points: [A, B, C, S1, S2]
  let fPoints = op.concat(proof.A, proof.B);
  fPoints = op.concat(fPoints, proof.C);
  fPoints = op.concat(fPoints, vk.S1);
  fPoints = op.concat(fPoints, vk.S2);

  // Scalars: [v1, v2, v3, v4, v5]
  let fScalars = op.concat(
    (challenges.v[1] as Uint256).bytes,
    (challenges.v[2] as Uint256).bytes
  );
  fScalars = op.concat(fScalars, (challenges.v[3] as Uint256).bytes);
  fScalars = op.concat(fScalars, (challenges.v[4] as Uint256).bytes);
  fScalars = op.concat(fScalars, (challenges.v[5] as Uint256).bytes);

  const fBatched = op.EllipticCurve.scalarMulMulti(op.Ec.BLS12_381g1, fPoints, fScalars);
  const F = g1Add(D, fBatched.toFixed({ length: 96 }));
  
  return { D, F };
}

/**
 * Calculate batched evaluation commitment E on the base [1]_1.
 *
 * E = (v1*a + v2*b + v3*c + v4*s1 + v5*s2 + u*zw - r0) * [1]_1
 * All field scalars are 32-byte big-endian; [1]_1 is G1_ONE.
 */
export function calculateE(
  proof: Proof,
  challenges: Challenges,
  r0: Uint256,
): bytes<96> {
  let e = frSub(
    frMul((challenges.v[1] as Uint256).native, proof.eval_a.native),
    r0.native,
  );
  e = frAdd(e, frMul((challenges.v[2] as Uint256).native, proof.eval_b.native));
  e = frAdd(e, frMul((challenges.v[3] as Uint256).native, proof.eval_c.native));
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

/**
 * Final pairing check (SNARKJS batching):
 *
 * A1 = Wξ + u·Wξω
 * B1 = ξ·Wξ + u·ξ·ω·Wξω + F − E
 * Check: e(−A1, [x]_2) * e(B1, [1]_2) = 1
 *
 * Encoding: G1 points are 96B uncompressed; G2 are 192B uncompressed (BE).
 * Assumes inputs are valid subgroup points produced by SNARKJS; AVM enforces encoding.
 */
export function isValidPairing(
  proof: Proof,
  challenges: Challenges,
  vk: VerificationKey,
  E: bytes<96>,
  F: bytes<96>,
): boolean {
  // A1 = Wxi + u * Wxiw (combined opening proofs for xi and xi*ω)
  let A1 = proof.Wxi;
  A1 = g1Add(A1, g1TimesFr(proof.Wxiw, challenges.u.native));

  // B1 = xi*Wxi + u*xi*ω*Wxiw + F - E
  // Concatenate points: Wxi || Wxiw
  const pairingPoints = op.concat(proof.Wxi, proof.Wxiw);

  // Concatenate scalars: xi || (u * xi * ω)
  const s = frMul(
    frMul(challenges.u.native, challenges.xi.native),
    ROOT_OF_UNITY,
  );
  const pairingScalars = op.concat(challenges.xi.bytes, b32(s));

  let B1 = op.EllipticCurve.scalarMulMulti(op.Ec.BLS12_381g1, pairingPoints, pairingScalars).toFixed({ length: 96 });
  B1 = g1Add(B1, F);
  B1 = g1Sub(B1, E);

  namedLog("A1", A1);
  namedLog("B1", B1);
  namedLog("neg(A1)", g1Neg(A1));
  namedLog("vk.X_2", vk.X_2);
  namedLog("G2_ONE", G2_ONE);

  // Final pairing check: e(-A1, [x]_2) * e(B1, [1]_2) = 1
  const res = op.EllipticCurve.pairingCheck(
    op.Ec.BLS12_381g1,
    op.concat(g1Neg(A1), B1), // G1 points
    op.concat(vk.X_2, G2_ONE), // G2 points
  );

  return res;
}

/**
 * Encoding & Endianness summary
 * - Field elements: 32-byte big-endian
 * - G1: 96-byte uncompressed x||y (BE)
 * - G2: 192-byte uncompressed x.c0||x.c1||y.c0||y.c1 (each 48-byte BE)
 * - Transcript concatenation order is documented in computeChallenges()
 */
