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
 * PLONK Zero-Knowledge Proof Verifier for BLS12-381 Elliptic Curve
 *
 * This implementation follows the PLONK protocol for verifying zero-knowledge proofs:
 * 1. Compute Fiat-Shamir challenges from the proof transcript
 * 2. Calculate Lagrange polynomial evaluations for public inputs
 * 3. Verify the linearization polynomial (gate constraints + permutation argument)
 * 4. Perform batch opening proof verification using polynomial commitments
 * 5. Execute final pairing check to confirm proof validity
 *
 * The verifier operates over the BLS12-381 scalar field Fr and uses elliptic curve
 * operations on G1 and G2 groups for polynomial commitment verification.
 */

// Generator point for BLS12-381 G1 group (uncompressed format)
const G1_ONE = Bytes.fromHex(
  "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
);

// Generator point for BLS12-381 G2 group (uncompressed format)
const G2_ONE = Bytes.fromHex(
  "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
);

/** Fr.w[11] precomputed by scripts/constants.ts */
const Frw11 = BigUint(
  Bytes.fromHex(
    "43527a8bca252472eb674a1a620890d7a534af14b61e0abe74a1f6718c130477",
  ),
);

/** BLS12-381 scalar field modulus (Fr) */
const BLS12_381_SCALAR_MODULUS = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
  ),
);

// Multiplication in the scalar field Fr
function frMul(a: biguint, b: biguint): biguint {
  return (a * b) % BLS12_381_SCALAR_MODULUS;
}

// BLS12_381_SCALAR_MODULUS - 1, used for point negation
const R_MINUS_1 = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
  ),
);

// BLS12_381_SCALAR_MODULUS - 2, used for modular inverse via Fermat's little theorem
// For prime p, Fermat's little theorem states: a^(p-2) ≡ a^(-1) (mod p) when gcd(a,p) = 1
const BLS12_381_R_MINUS_2 = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffeffffffff",
  ),
);

/**
 * Fast modular exponentiation using binary method (square-and-multiply)
 * Computes base^exp mod mod efficiently in O(log exp) time
 *
 * Algorithm:
 * 1. Initialize result = 1, b = base mod mod
 * 2. For each bit in exp (from LSB to MSB):
 *    - If bit is 1: result = (result * b) mod mod
 *    - Square b: b = (b * b) mod mod
 *    - Shift exp right by 1 bit
 * 3. Return result
 *
 * This avoids computing base^exp directly, which would be astronomically large
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

// Modular inverse in Fr using Fermat's little theorem: a^(p-2) ≡ a^(-1) (mod p)
function frInv(b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const x = frScalar(BigUint(b));
  assert(x !== (0n as biguint), "Fr inverse of zero");
  const inv = modPow(x, BLS12_381_R_MINUS_2, r);
  return inv;
}

// Division in Fr: a / b = a * b^(-1)
function frDiv(a: biguint, b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN = frScalar(BigUint(a));
  const bInv = BigUint(frInv(b));
  return (aN * bInv) % r;
}

// Subtraction in Fr with proper modular arithmetic
function frSub(a: biguint, b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN: biguint = a % r;
  const bN: biguint = b % r;
  return (aN + r - bN) % r;
}

// Addition in Fr
function frAdd(a: biguint, b: biguint): biguint {
  const r = BLS12_381_SCALAR_MODULUS;
  const aN: biguint = a % r;
  const bN: biguint = b % r;
  return (aN + bN) % r;
}

// Reduce to canonical form in Fr
function frScalar(a: biguint): biguint {
  return a % BLS12_381_SCALAR_MODULUS;
}

// Convert biguint to 32-byte representation
function b32(a: biguint): bytes<32> {
  return new Uint256(a).bytes.toFixed({ length: 32 });
}

export type PublicSignals = Uint256[];

// PLONK proof structure containing G1 points and field evaluations
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

// Fiat-Shamir challenges derived during verification
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

// Debug logging helper
function namedLog(name: string, value: bytes): void {
  log(name);
  log(value);
}

// Scalar multiplication on G1: p * s
function g1TimesFr(p: bytes<96>, s: biguint): bytes<96> {
  return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    length: 96,
  });
}

// Point addition on G1
function g1Add(p1: bytes<96>, p2: bytes<96>): bytes<96> {
  return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    length: 96,
  });
}

// Point negation on G1
function g1Neg(p: bytes<96>): bytes<96> {
  return g1TimesFr(p, R_MINUS_1);
}

// Point subtraction on G1: p - q
function g1Sub(p: bytes<96>, q: bytes<96>): bytes<96> {
  return g1Add(p, g1Neg(q));
}

// PLONK verification key containing circuit-specific parameters
export type VerificationKey = {
  Qm: bytes<96>; // Multiplication gate selector
  Ql: bytes<96>; // Left wire selector
  Qr: bytes<96>; // Right wire selector
  Qo: bytes<96>; // Output wire selector
  Qc: bytes<96>; // Constant selector
  S1: bytes<96>; // Permutation polynomial S_σ(1)
  S2: bytes<96>; // Permutation polynomial S_σ(2)
  S3: bytes<96>; // Permutation polynomial S_σ(3)
  power: uint64; // Circuit size as power of 2
  nPublic: uint64; // Number of public inputs
  k1: uint64; // Permutation parameter
  k2: uint64; // Permutation parameter
  X_2: bytes<192>; // Trusted setup parameter in G2
};

// Verify proof using verification key from template variable
export function verifyFromTemplate(
  signals: PublicSignals,
  proof: Proof,
): boolean {
  const vkBytes = TemplateVar<bytes>("VERIFICATION_KEY");

  // Parse verification key from serialized bytes
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

// Main PLONK verification function
export function verify(
  vk: VerificationKey,
  signals: PublicSignals,
  proof: Proof,
): boolean {
  // Compute Fiat-Shamir challenges from transcript
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

  // Calculate Lagrange polynomial evaluations at xi
  const { L, challenges: updatedChallenges } = calculateLagrangeEvaluations(
    challenges,
    vk,
  );

  namedLog("L1(xi)", (L[1] as Uint256).bytes);

  challenges = clone(updatedChallenges);

  // Calculate public input polynomial evaluation
  const pi = calculatePI(signals, L);
  namedLog("PI(xi)", pi.bytes);

  // Calculate linearization polynomial constant term
  const r0 = calculateR0(proof, challenges, pi, L[1] as Uint256);
  namedLog("r0", r0.bytes);

  // Calculate linearization polynomial commitment
  const d = calculateD(proof, challenges, vk, L[1] as Uint256);
  namedLog("D", d);

  // Batch opening proof verification - compute F
  const f = calculateF(proof, challenges, vk, d);
  namedLog("F", f);

  // Batch opening proof verification - compute E
  const e = calculateE(proof, challenges, r0);
  namedLog("E", e);

  // Final pairing check
  return isValidPairing(proof, challenges, vk, e, f);
}

// Generate Fiat-Shamir challenge by hashing transcript data
export function getChallenge(td: bytes): Uint256 {
  let hash = op.keccak256(td);
  return new Uint256(frScalar(BigUint(hash)));
}

// Compute all Fiat-Shamir challenges following PLONK protocol
export function computeChallenges(
  vk: VerificationKey,
  signals: PublicSignals,
  proof: Proof,
): Challenges {
  /////////////////////////////////////
  // Challenge round 2: beta and gamma
  ////////////////////////////////////
  // Build transcript with verification key and public inputs
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

  // gamma challenge
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

  // Generate batch opening challenges v[1], v[2], ..., v[5]
  const v = new FixedArray<Uint256, 6>();
  v[1] = getChallenge(td);

  for (let i: uint64 = 2; i < 6; i++) {
    v[i] = new Uint256(frMul((v[i - 1] as Uint256).native, v[1].native));
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

// Calculate Lagrange polynomial evaluations L_i(xi) for public inputs
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
  challenges.zh = new Uint256(frSub(xin, BigUint(1))); // Vanishing polynomial Z_H(xi)

  const n = frScalar(BigUint(domainSize));

  let w = BigUint(1); // Root of unity

  // Calculate Lagrange basis polynomials L_i(xi) = ω^(i-1) * Z_H(xi) / (n * (xi - ω^(i-1)))
  // where ω is the primitive nth root of unity, Z_H(xi) is the vanishing polynomial,
  // and n is the domain size. These polynomials interpolate public inputs.
  const L: Uint256[] = [new Uint256(), new Uint256()];
  const iterations: uint64 = vk.nPublic === 0 ? 1 : vk.nPublic;
  for (let i: uint64 = 1; i <= iterations; i++) {
    L[i] = new Uint256(
      frDiv(
        frMul(w, challenges.zh.native),
        frMul(n, frSub(challenges.xi.native, w)),
      ),
    );

    w = frMul(w, Frw11); // Next root of unity: ω^i
  }
  return { L, challenges };
}

// Calculate public input polynomial evaluation PI(xi) = -∑(w_i * L_i(xi))
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
 * Calculate linearization polynomial constant term r0
 *
 * The linearization polynomial r(X) represents the PLONK relation at the challenge point xi.
 * r0 is the constant term when r(X) is written as r(X) = r0 + r1*X + ... + rn*X^n.
 *
 * r0 = PI(xi) - L1(xi)*α² - α*Z(xi*ω)*[(a+β*s1+γ)(b+β*s2+γ)(c+γ)]
 *
 * Components:
 * - e1: Public input polynomial evaluation PI(xi)
 * - e2: Boundary constraint L1(xi)*α² (ensures Z(1) = 1 for permutation polynomial)
 * - e3: Permutation argument contribution from the grand product polynomial Z(x)
 */
export function calculateR0(
  proof: Proof,
  challenges: Challenges,
  pi: Uint256,
  l1: Uint256,
): Uint256 {
  // e1: Public input polynomial evaluation PI(xi)
  const e1 = pi.native;

  // e2: Boundary constraint L1(xi) * α² (ensures Z(1) = 1)
  const e2 = frMul(
    l1.native,
    frMul(challenges.alpha.native, challenges.alpha.native),
  );

  // e3: Permutation check contribution
  // Computes α * Z(xi*ω) * [(a + β*s1 + γ)(b + β*s2 + γ)(c + γ)]
  // This represents the "numerator" of the permutation argument
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
 * Calculate linearization polynomial commitment D
 *
 * The linearization polynomial D represents the PLONK relation as a polynomial commitment.
 * It combines four main components that must sum to zero for a valid proof:
 *
 * D = d1 + d2 - d3 - d4, where:
 * - d1: Gate constraints (arithmetic gates)
 * - d2: Permutation argument "numerator" (grand product polynomial Z)
 * - d3: Permutation argument "denominator" (sigma polynomial S3)
 * - d4: Quotient polynomial contribution (ensures degree bounds)
 *
 * This commitment will be opened at the challenge point xi to verify the relation holds.
 */
export function calculateD(
  proof: Proof,
  challenges: Challenges,
  vk: VerificationKey,
  l1: Uint256,
): bytes<96> {
  // d1: Gate constraints - evaluates arithmetic circuit gates
  // Computes: Qm*a*b + Ql*a + Qr*b + Qo*c + Qc
  let d1 = g1TimesFr(vk.Qm, frMul(proof.eval_a.native, proof.eval_b.native));
  d1 = g1Add(d1, g1TimesFr(vk.Ql, proof.eval_a.native));
  d1 = g1Add(d1, g1TimesFr(vk.Qr, proof.eval_b.native));
  d1 = g1Add(d1, g1TimesFr(vk.Qo, proof.eval_c.native));
  d1 = g1Add(d1, vk.Qc);

  const betaxi = frMul(challenges.beta.native, challenges.xi.native);

  // d2: Permutation argument "numerator" from grand product polynomial Z(x)
  // Represents the accumulating product that enforces copy constraints
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

  // d3: Permutation argument "denominator" from sigma polynomial S3(x)
  // Represents the expected permutation structure
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

  // d4: Quotient polynomial contribution - ensures the relation has correct degree
  // Reconstructs T(xi) = T1(xi) + xi^n*T2(xi) + xi^(2n)*T3(xi), then multiplies by Z_H(xi)
  const d4low = proof.T1;
  const d4mid = g1TimesFr(proof.T2, challenges.xin.native);
  const d4high = g1TimesFr(
    proof.T3,
    frMul(challenges.xin.native, challenges.xin.native),
  );
  let d4 = g1Add(d4low, g1Add(d4mid, d4high));
  d4 = g1TimesFr(d4, challenges.zh.native);

  // Final linearization: D = d1 + d2 - d3 - d4
  const d = g1Sub(g1Sub(g1Add(d1, d2), d3), d4);

  return d;
}

/**
 * Calculate batch opening proof F for polynomial commitments
 *
 * F represents a linear combination of all polynomial commitments that need to be
 * opened at the challenge point xi. This batching technique allows verifying
 * multiple polynomial evaluations with a single pairing check.
 *
 * F = D + v1*A + v2*B + v3*C + v4*S1 + v5*S2
 *
 * where v1, v2, ..., v5 are random challenges that ensure the batch opening
 * is sound (if any individual opening is incorrect, F will be incorrect with
 * overwhelming probability).
 */
export function calculateF(
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

/**
 * Calculate batch opening proof E for polynomial evaluations
 *
 * E represents the expected value when all polynomials in F are evaluated at xi.
 * This is the "right-hand side" of the batch opening equation.
 *
 * E = (v1*a + v2*b + v3*c + v4*s1 + v5*s2 + u*zw - r0) * G1
 *
 * Components:
 * - v1*a, v2*b, v3*c: Batched evaluations of witness polynomials A, B, C at xi
 * - v4*s1, v5*s2: Batched evaluations of permutation polynomials S1, S2 at xi
 * - u*zw: Evaluation of grand product polynomial Z at xi*ω (shifted point)
 * - r0: Linearization polynomial constant term (subtracted)
 *
 * The final pairing check will verify: e(F - E, [1]_2) = e(Wxi + u*Wxiw, [x]_2)
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
 * Final pairing check: e(-A1, X_2) * e(B1, [1]_2) = 1
 *
 * This is the core cryptographic verification that proves the polynomial commitments
 * are correctly opened. The pairing equation verifies that:
 *
 * (F - E) = (Wxi + u*Wxiw) * x
 *
 * where:
 * - F: Batch of polynomial commitments
 * - E: Batch of claimed evaluations
 * - Wxi: Opening proof for evaluations at xi
 * - Wxiw: Opening proof for evaluations at xi*ω
 * - x: Trusted setup parameter (secret evaluation point)
 *
 * The equation is rearranged as: e(-(Wxi + u*Wxiw), [x]_2) * e(F - E + xi*Wxi + u*xi*ω*Wxiw, [1]_2) = 1
 *
 * If this pairing equation holds, it cryptographically proves that all polynomial
 * evaluations are consistent with their commitments, completing the PLONK verification.
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
  // This represents the "quotient" side of the opening equation
  let B1 = g1TimesFr(proof.Wxi, challenges.xi.native);
  const s = frMul(frMul(challenges.u.native, challenges.xi.native), Frw11);
  B1 = g1Add(B1, g1TimesFr(proof.Wxiw, s));
  B1 = g1Add(B1, F);
  B1 = g1Sub(B1, E);

  namedLog("A1", A1);
  namedLog("B1", B1);
  namedLog("neg(A1)", g1Neg(A1));
  namedLog("vk.X_2", vk.X_2);
  namedLog("G2_ONE", G2_ONE);

  // Final pairing check: e(-A1, [x]_2) * e(B1, [1]_2) = 1
  // This verifies the polynomial opening equation holds
  const res = op.EllipticCurve.pairingCheck(
    op.Ec.BLS12_381g1,
    op.concat(g1Neg(A1), B1), // G1 points
    op.concat(vk.X_2, G2_ONE), // G2 points
  );

  return res;
}
