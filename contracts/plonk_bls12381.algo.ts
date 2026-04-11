import {
  type bytes,
  op,
  BigUint,
  FixedArray,
  type uint64,
  Bytes,
  type biguint,
  assert,
  clone,
  TemplateVar,
} from "@algorandfoundation/algorand-typescript";
import {
  decodeArc4,
  Uint256,
} from "@algorandfoundation/algorand-typescript/arc4";
import {
  BLS12_381_SCALAR_MODULUS,
  frScalar,
  b32,
  debugLog,
  g1TimesFr,
  g1Add,
  g1Neg,
  inField,
  type PublicSignals,
} from "./bls12381_common.algo";

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
 *
 * It should be noted that most of this code is a direct translation of the snarkjs verifier
 *
 * The only deviations are some MSMs to save on opcode cost. There is also an additional opportunity for an MSM across
 * D, F, and the pairing check
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
 * Primitive root of unity in the BLS12-381 scalar field Fr.
 */
const ROOT_OF_UNITY = TemplateVar<biguint>("ROOT_OF_UNITY");

/**
 * Multiplication in the scalar field Fr.
 * Computes (a * b) mod r where r is the BLS12-381 scalar field modulus.
 * Returns the canonical representative in [0, r-1].
 */
function frMul(a: biguint, b: biguint): biguint {
  return (a * b) % BLS12_381_SCALAR_MODULUS;
}

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

export type LagrangeWitness = {
  // L[0..iterations-1] where iterations = max(nPublic,1); L[0] corresponds to L1(ξ)
  L: Uint256[];
  xin: Uint256; // ξ^n
  zh: Uint256; // ξ^n − 1
};

/**
 * PLONK proof structure: G1 points (96B BE) and field evals (32B BE)
 */
export type PlonkProof = {
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
export type PlonkVerificationKey = {
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
 * Verify proof using verification key from template variable with debug logging
 */
export function verifyPlonkFromTemplateWithLogs(
  signals: PublicSignals,
  proof: PlonkProof,
): boolean {
  const vkBytes = TemplateVar<bytes>("VERIFICATION_KEY");

  return verifyWithLogs(
    decodeArc4<PlonkVerificationKey>(vkBytes),
    signals,
    proof,
  );
}

/**
 * Verify proof using verification key from template variable
 */
export function verifyPlonkFromTemplate(
  signals: PublicSignals,
  proof: PlonkProof,
): boolean {
  const vkBytes = TemplateVar<bytes>("VERIFICATION_KEY");

  return verify(decodeArc4<PlonkVerificationKey>(vkBytes), signals, proof);
}

function groupCheck(p: bytes<96>): boolean {
  return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
}

function assertSignalsInField(
  vk: PlonkVerificationKey,
  signals: PublicSignals,
) {
  assert(signals.length === vk.nPublic, "Invalid number of public inputs");

  for (const signal of signals) {
    assert(inField(signal), "public signal not in Fr");
  }
}

function assertEvalsInField(proof: PlonkProof) {
  assert(inField(proof.eval_a), "eval_a not in Fr");
  assert(inField(proof.eval_b), "eval_b not in Fr");
  assert(inField(proof.eval_c), "eval_c not in Fr");
  assert(inField(proof.eval_s1), "eval_s1 not in Fr");
  assert(inField(proof.eval_s2), "eval_s2 not in Fr");
  assert(inField(proof.eval_zw), "eval_zw not in Fr");
}

function assertProofInSubgroup(proof: PlonkProof) {
  assert(groupCheck(proof.A), "A not in G1");
  assert(groupCheck(proof.B), "B not in G1");
  assert(groupCheck(proof.C), "C not in G1");
  assert(groupCheck(proof.Z), "Z not in G1");
  assert(groupCheck(proof.T1), "T1 not in G1");
  assert(groupCheck(proof.T2), "T2 not in G1");
  assert(groupCheck(proof.T3), "T3 not in G1");
  assert(groupCheck(proof.Wxi), "Wxi not in G1");
  assert(groupCheck(proof.Wxiw), "Wxiw not in G1");
}

export function validateInput(
  vk: PlonkVerificationKey,
  signals: PublicSignals,
  proof: PlonkProof,
): void {
  assertProofInSubgroup(proof);
  assertEvalsInField(proof);
  assertSignalsInField(vk, signals);
}

/**
 * Main PLONK verification function
 */
export function verify(
  vk: PlonkVerificationKey,
  signals: PublicSignals,
  proof: PlonkProof,
): boolean {
  validateInput(vk, signals, proof);

  // 1) Fiat–Shamir challenges from transcript (SNARKJS chaining)
  let initialChallenges = computeChallenges(vk, signals, proof);

  // 2) Validate provided Lagrange evaluations and associated witness (off-chain computed)
  const lw = calculateLagrangeEvaluations(initialChallenges, vk);
  const challenges = clone(lw.challenges);

  // 3) Public input polynomial at ξ using provided Lagrange evaluations
  const pi = calculatePI(signals, lw.L);

  // 4) Linearization polynomial constant term r0
  const r0 = calculateR0(proof, challenges, pi, lw.L[1] as Uint256);

  // 5) Linearization commitment D and batch opening commitment F (optimized)
  const f = calculateDFCombinedMsm(proof, challenges, vk, lw.L[1]!);

  // 7) Batched evaluation commitment E (on [1]_1)
  const e = calculateE(proof, challenges, r0);

  // 8) Final pairing check
  return isValidPairing(proof, challenges, vk, e, f);
}

/**
 * Main PLONK verification function with debug logging
 */
export function verifyWithLogs(
  vk: PlonkVerificationKey,
  signals: PublicSignals,
  proof: PlonkProof,
): boolean {
  validateInput(vk, signals, proof);

  // 1) Fiat–Shamir challenges from transcript (SNARKJS chaining)
  let initialChallenges = computeChallenges(vk, signals, proof);
  debugLog("beta", initialChallenges.beta.bytes);
  debugLog("gamma", initialChallenges.gamma.bytes);
  debugLog("alpha", initialChallenges.alpha.bytes);
  debugLog("xi", initialChallenges.xi.bytes);
  debugLog("u", initialChallenges.u.bytes);

  // 2) Validate provided Lagrange evaluations and set xin/zh
  const lw = calculateLagrangeEvaluations(initialChallenges, vk);
  const challenges = clone(lw.challenges);

  debugLog("xin", challenges.xin.bytes);
  debugLog("zh", challenges.zh.bytes);
  debugLog("v[1]", (challenges.v[1] as Uint256).bytes);
  debugLog("v[2]", (challenges.v[2] as Uint256).bytes);
  debugLog("v[3]", (challenges.v[3] as Uint256).bytes);
  debugLog("v[4]", (challenges.v[4] as Uint256).bytes);
  debugLog("v[5]", (challenges.v[5] as Uint256).bytes);

  // 3) Public input polynomial at ξ (using provided L)
  const pi = calculatePI(signals, lw.L);
  debugLog("L1(xi)", (lw.L[1] as Uint256).bytes);
  debugLog("PI(xi)", pi.bytes);

  // 4) Linearization polynomial constant term r0
  const r0 = calculateR0(proof, challenges, pi, lw.L[1] as Uint256);
  debugLog("r0", r0.bytes);

  // 5) Linearization commitment D and batch opening commitment F (optimized)
  const f = calculateDFCombinedMsm(proof, challenges, vk, lw.L[1]!);

  debugLog("F", f);

  // 7) Batched evaluation commitment E (on [1]_1)
  const e = calculateE(proof, challenges, r0);
  debugLog("E", e);

  // 8) Final pairing check
  return isValidPairing(proof, challenges, vk, e, f);
}

/**
 * Derive a challenge by hashing the current transcript chunk, reduced to Fr
 *
 * See https://github.com/iden3/snarkjs/blob/1de7c8a7470c4b10a04fca2cc1037c97767a8211/src/Keccak256Transcript.js#L46-L46
 */
export function getChallenge(td: bytes): Uint256 {
  let hash = op.keccak256(td);
  return new Uint256(frScalar(BigUint(hash)));
}

/**
 * Compute all Fiat–Shamir challenges following SNARKJS transcript chaining
 *
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L208-L208
 */
export function computeChallenges(
  vk: PlonkVerificationKey,
  signals: PublicSignals,
  proof: PlonkProof,
): Challenges {
  /////////////////////////////////////
  // Challenge round 2: beta and gamma
  /////////////////////////////////////
  // Build transcript with verification key commitments and public inputs
  let td = vk.Qm.concat(vk.Ql)
    .concat(vk.Qr)
    .concat(vk.Qo)
    .concat(vk.Qc)
    .concat(vk.S1)
    .concat(vk.S2)
    .concat(vk.S3);

  for (const signal of signals) {
    td = td.concat(b32(frScalar(signal.asBigUint())));
  }

  // Add round 1 commitments
  td = td.concat(proof.A).concat(proof.B).concat(proof.C);

  const beta = getChallenge(td);

  // gamma challenge (chaining): gamma = H(beta)
  const gamma = getChallenge(beta.bytes);

  ////////////////////////////
  // Challenge round 3: alpha
  ////////////////////////////
  const alpha = getChallenge(beta.bytes.concat(gamma.bytes).concat(proof.Z));

  ////////////////////////////
  // Challenge round 4: xi
  ///////////////////////////
  const xi = getChallenge(
    alpha.bytes.concat(proof.T1).concat(proof.T2).concat(proof.T3),
  );

  ////////////////////////////
  // Challenge round 5: v (powers of v1)
  //////////////////////////
  const v = new FixedArray<Uint256, 6>();
  v[1] = getChallenge(
    xi.bytes
      .concat(proof.eval_a.bytes)
      .concat(proof.eval_b.bytes)
      .concat(proof.eval_c.bytes)
      .concat(proof.eval_s1.bytes)
      .concat(proof.eval_s2.bytes)
      .concat(proof.eval_zw.bytes),
  ); // v1
  for (let i: uint64 = 2; i < 6; i++) {
    v[i] = new Uint256(
      frMul((v[i - 1] as Uint256).asBigUint(), v[1].asBigUint()),
    ); // v[i] = v1^i
  }

  ////////////////////////////
  // Challenge: u
  /////////////////////////////
  const u = getChallenge(proof.Wxi.concat(proof.Wxiw));

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
 *
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L275-L275
 */
export function calculateLagrangeEvaluations(
  challengesInput: Challenges,
  vk: PlonkVerificationKey,
): { L: Uint256[]; challenges: Challenges } {
  const challenges = clone(challengesInput);
  let xin = challenges.xi.asBigUint();

  let domainSize: uint64 = 1;
  for (let i: uint64 = 0; i < vk.power; i++) {
    xin = frMul(xin, xin);
    domainSize *= 2;
  }

  challenges.xin = new Uint256(xin);
  challenges.zh = new Uint256(frSub(xin, BigUint(1)));

  const n = frScalar(BigUint(domainSize));

  let w = BigUint(1);

  const L: Uint256[] = [new Uint256()];

  const iterations: uint64 = vk.nPublic === 0 ? 1 : vk.nPublic;
  for (let i: uint64 = 1; i <= iterations; i++) {
    L.push(
      new Uint256(
        frDiv(
          frMul(w, challenges.zh.asBigUint()),
          frMul(n, frSub(challenges.xi.asBigUint(), w)),
        ),
      ),
    );
    w = frMul(w, ROOT_OF_UNITY);
  }
  return { L, challenges };
}

/**
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L300-L300
 */
export function calculatePI(
  publicSignals: PublicSignals,
  L: Uint256[],
): Uint256 {
  let pi = BigUint(0);
  for (let i: uint64 = 0; i < publicSignals.length; i++) {
    const w = frScalar((publicSignals[i] as Uint256).asBigUint());
    pi = frSub(pi, frMul(w, (L[i + 1] as Uint256).asBigUint()));
  }
  return new Uint256(pi);
}

/**
 * Calculate linearization polynomial constant term r0.
 *
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L311-L311
 */
export function calculateR0(
  proof: PlonkProof,
  challenges: Challenges,
  pi: Uint256,
  l1: Uint256,
): Uint256 {
  const e1 = pi.asBigUint();

  const e2 = frMul(
    l1.asBigUint(),
    frMul(challenges.alpha.asBigUint(), challenges.alpha.asBigUint()),
  );

  let e3a = frAdd(
    proof.eval_a.asBigUint(),
    frMul(challenges.beta.asBigUint(), proof.eval_s1.asBigUint()),
  );
  e3a = frAdd(e3a, challenges.gamma.asBigUint());

  let e3b = frAdd(
    proof.eval_b.asBigUint(),
    frMul(challenges.beta.asBigUint(), proof.eval_s2.asBigUint()),
  );
  e3b = frAdd(e3b, challenges.gamma.asBigUint());

  let e3c = frAdd(proof.eval_c.asBigUint(), challenges.gamma.asBigUint());

  let e3 = frMul(frMul(e3a, e3b), e3c);
  e3 = frMul(e3, proof.eval_zw.asBigUint());
  e3 = frMul(e3, challenges.alpha.asBigUint());

  // r0 = e1 - e2 - e3
  const r0 = frSub(frSub(e1, e2), e3);
  return new Uint256(r0);
}

/* A direct translation of the d1 calculation from snarkjs. This function is not used in favor of calculateD1Msm, but included for posterity
 *
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L339-L343
 */
function calculateD1(proof: PlonkProof, vk: PlonkVerificationKey) {
  let d1 = g1TimesFr(
    vk.Qm,
    frMul(proof.eval_a.asBigUint(), proof.eval_b.asBigUint()),
  );
  d1 = g1Add(d1, g1TimesFr(vk.Ql, proof.eval_a.asBigUint()));
  d1 = g1Add(d1, g1TimesFr(vk.Qr, proof.eval_b.asBigUint()));
  d1 = g1Add(d1, g1TimesFr(vk.Qo, proof.eval_c.asBigUint()));
  d1 = g1Add(d1, vk.Qc);

  return d1;
}

/* A translation of the d1 calculation from snarkjs using MSM
 *
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L339-L343
 */
function calculateD1Msm(proof: PlonkProof, vk: PlonkVerificationKey) {
  // Concatenate all G1 points (5 points = 480 bytes)
  const points = vk.Qm.concat(vk.Ql).concat(vk.Qr).concat(vk.Qo).concat(vk.Qc);

  // Calculate the 5 scalars
  const scalarQm = frMul(proof.eval_a.asBigUint(), proof.eval_b.asBigUint());
  const scalarQl = proof.eval_a.asBigUint();
  const scalarQr = proof.eval_b.asBigUint();
  const scalarQo = proof.eval_c.asBigUint();
  const scalarQc = BigUint(1); // Qc is added directly (multiplied by 1)

  // Concatenate all scalars (5 scalars = 160 bytes, 32 bytes each)
  const scalars = b32(frScalar(scalarQm))
    .concat(b32(frScalar(scalarQl)))
    .concat(b32(frScalar(scalarQr)))
    .concat(b32(frScalar(scalarQo)))
    .concat(b32(frScalar(scalarQc)));

  // Single MSM computes: Qm*(eval_a*eval_b) + Ql*eval_a + Qr*eval_b + Qo*eval_c + Qc*1
  return op.EllipticCurve.scalarMulMulti(
    op.Ec.BLS12_381g1,
    points,
    scalars,
  ).toFixed({ length: 96 });
}

/* A direct translation of the d4 calculation from snarkjs. This function is not used in favor of calculateD4Msm, but included for posterity
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L363-L367
 */
function calculateD4(proof: PlonkProof, challenges: Challenges) {
  const d4low = proof.T1;
  const d4Mid = g1TimesFr(proof.T2, challenges.xin.asBigUint());
  const d4High = g1TimesFr(
    proof.T3,
    frMul(challenges.xin.asBigUint(), challenges.xin.asBigUint()),
  );

  let d4 = g1Add(d4low, g1Add(d4Mid, d4High));
  d4 = g1TimesFr(d4, challenges.zh.asBigUint());
}

/* A translation of the d4 calculation from snarkjs using MSM
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L363-L367
 */
function calculateD4Msm(proof: PlonkProof, challenges: Challenges): bytes<96> {
  const points = proof.T1.concat(proof.T2).concat(proof.T3);

  const xin = challenges.xin.asBigUint();
  const zh = challenges.zh.asBigUint();

  const scalars = b32(frScalar(zh)) // T1 * zh
    .concat(b32(frScalar(frMul(xin, zh)))) // T2 * (xin * zh)
    .concat(b32(frScalar(frMul(frMul(xin, xin), zh)))); // T3 * (xin² * zh)

  return op.EllipticCurve.scalarMulMulti(
    op.Ec.BLS12_381g1,
    points,
    scalars,
  ).toFixed({ length: 96 });
}

/**
 * Translation of calculateD from snarkjs with MSM. This function is not used in favor of calculateDFCombinedMSM
 * but included for posterity
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L335-L335
 */
function calculateD(
  proof: PlonkProof,
  challenges: Challenges,
  vk: PlonkVerificationKey,
  l1: Uint256,
): bytes<96> {
  const d1 = calculateD1Msm(proof, vk);

  const betaxi = frMul(challenges.beta.asBigUint(), challenges.xi.asBigUint());

  const d2a1 = frAdd(
    frAdd(proof.eval_a.asBigUint(), betaxi),
    challenges.gamma.asBigUint(),
  );
  const d2a2 = frAdd(
    frAdd(proof.eval_b.asBigUint(), frMul(betaxi, BigUint(vk.k1))),
    challenges.gamma.asBigUint(),
  );
  const d2a3 = frAdd(
    frAdd(proof.eval_c.asBigUint(), frMul(betaxi, BigUint(vk.k2))),
    challenges.gamma.asBigUint(),
  );

  const d2a = frMul(
    frMul(frMul(d2a1, d2a2), d2a3),
    challenges.alpha.asBigUint(),
  );

  const d2b = frMul(
    l1.asBigUint(),
    frMul(challenges.alpha.asBigUint(), challenges.alpha.asBigUint()),
  );

  const d2 = g1TimesFr(
    proof.Z,
    frAdd(frAdd(d2a, d2b), challenges.u.asBigUint()),
  );

  const d3a = frAdd(
    frAdd(
      proof.eval_a.asBigUint(),
      frMul(challenges.beta.asBigUint(), proof.eval_s1.asBigUint()),
    ),
    challenges.gamma.asBigUint(),
  );

  const d3b = frAdd(
    frAdd(
      proof.eval_b.asBigUint(),
      frMul(challenges.beta.asBigUint(), proof.eval_s2.asBigUint()),
    ),
    challenges.gamma.asBigUint(),
  );

  const d3c = frMul(
    frMul(challenges.alpha.asBigUint(), challenges.beta.asBigUint()),
    proof.eval_zw.asBigUint(),
  );

  const d3 = g1TimesFr(vk.S3, frMul(frMul(d3a, d3b), d3c));

  const d4 = calculateD4Msm(proof, challenges);
  const d = g1Sub(g1Sub(g1Add(d1, d2), d3), d4);

  return d;
}

/**
 * Direct translation of calculateF. This function is not used in favor of calculateFMsm, but included for posterity
 *
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L374-L374
 */
function calculateF(
  proof: PlonkProof,
  challenges: Challenges,
  vk: PlonkVerificationKey,
  D: bytes<96>,
): bytes<96> {
  let res = g1Add(D, g1TimesFr(proof.A, challenges.v[1]!.asBigUint()));
  res = g1Add(res, g1TimesFr(proof.B, challenges.v[2]!.asBigUint()));
  res = g1Add(res, g1TimesFr(proof.C, challenges.v[3]!.asBigUint()));
  res = g1Add(res, g1TimesFr(vk.S1, challenges.v[4]!.asBigUint()));
  res = g1Add(res, g1TimesFr(vk.S2, challenges.v[5]!.asBigUint()));

  return res;
}

/**
 * Translation of the snarkJS calculateF function with MSM. This function is not used in favor of calculateDFCombinedMSM
 * but included for posterity
 *
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L374-L374
 */
function calculateFMsm(
  proof: PlonkProof,
  challenges: Challenges,
  vk: PlonkVerificationKey,
  D: bytes<96>,
) {
  // Concatenate all G1 points (6 points = 576 bytes)
  const points = D.concat(proof.A)
    .concat(proof.B)
    .concat(proof.C)
    .concat(vk.S1)
    .concat(vk.S2);

  // D gets scalar 1, others get their respective v values
  const scalars = b32(frScalar(BigUint(1)))
    .concat(b32(frScalar(challenges.v[1]!.asBigUint())))
    .concat(b32(frScalar(challenges.v[2]!.asBigUint())))
    .concat(b32(frScalar(challenges.v[3]!.asBigUint())))
    .concat(b32(frScalar(challenges.v[4]!.asBigUint())))
    .concat(b32(frScalar(challenges.v[5]!.asBigUint())));

  // Single MSM computes: D*1 + A*v[1] + B*v[2] + C*v[3] + S1*v[4] + S2*v[5]
  return op.EllipticCurve.scalarMulMulti(
    op.Ec.BLS12_381g1,
    points,
    scalars,
  ).toFixed({ length: 96 });
}

/*
 * A translation of calculateD and calculateF combined with a single MSM
 */
function calculateDFCombinedMsm(
  proof: PlonkProof,
  challenges: Challenges,
  vk: PlonkVerificationKey,
  l1: Uint256,
): bytes<96> {
  const r = BLS12_381_SCALAR_MODULUS;

  // Calculate all 14 scalars upfront

  // D1 scalars
  const sQm = frMul(proof.eval_a.asBigUint(), proof.eval_b.asBigUint());
  const sQl = proof.eval_a.asBigUint();
  const sQr = proof.eval_b.asBigUint();
  const sQo = proof.eval_c.asBigUint();
  const sQc = BigUint(1);

  // D2 scalar
  const betaxi = frMul(challenges.beta.asBigUint(), challenges.xi.asBigUint());
  const d2a1 = frAdd(
    frAdd(proof.eval_a.asBigUint(), betaxi),
    challenges.gamma.asBigUint(),
  );
  const d2a2 = frAdd(
    frAdd(proof.eval_b.asBigUint(), frMul(betaxi, BigUint(vk.k1))),
    challenges.gamma.asBigUint(),
  );
  const d2a3 = frAdd(
    frAdd(proof.eval_c.asBigUint(), frMul(betaxi, BigUint(vk.k2))),
    challenges.gamma.asBigUint(),
  );
  const d2a = frMul(
    frMul(frMul(d2a1, d2a2), d2a3),
    challenges.alpha.asBigUint(),
  );
  const d2b = frMul(
    l1.asBigUint(),
    frMul(challenges.alpha.asBigUint(), challenges.alpha.asBigUint()),
  );
  const sZ = frAdd(frAdd(d2a, d2b), challenges.u.asBigUint());

  // D3 scalar
  const d3a = frAdd(
    frAdd(
      proof.eval_a.asBigUint(),
      frMul(challenges.beta.asBigUint(), proof.eval_s1.asBigUint()),
    ),
    challenges.gamma.asBigUint(),
  );
  const d3b = frAdd(
    frAdd(
      proof.eval_b.asBigUint(),
      frMul(challenges.beta.asBigUint(), proof.eval_s2.asBigUint()),
    ),
    challenges.gamma.asBigUint(),
  );
  const d3c = frMul(
    frMul(challenges.alpha.asBigUint(), challenges.beta.asBigUint()),
    proof.eval_zw.asBigUint(),
  );
  // Negate by computing r - scalar
  const sS3 = frSub(r, frMul(frMul(d3a, d3b), d3c));

  // D4 scalars (all negative - quotient terms subtracted)
  const xin = challenges.xin.asBigUint();
  const zh = challenges.zh.asBigUint();
  const sT1 = frSub(r, zh); // T1 × (-zh)
  const sT2 = frSub(r, frMul(xin, zh)); // T2 × (-xin×zh)
  const sT3 = frSub(r, frMul(frMul(xin, xin), zh)); // T3 × (-xin²×zh)

  // F scalars (v values)
  const sA = challenges.v[1]!.asBigUint();
  const sB = challenges.v[2]!.asBigUint();
  const sC = challenges.v[3]!.asBigUint();
  const sS1 = challenges.v[4]!.asBigUint();
  const sS2 = challenges.v[5]!.asBigUint();

  // Concatenate all 14 points
  const points = vk.Qm.concat(vk.Ql)
    .concat(vk.Qr)
    .concat(vk.Qo)
    .concat(vk.Qc)
    .concat(proof.Z)
    .concat(vk.S3)
    .concat(proof.T1)
    .concat(proof.T2)
    .concat(proof.T3)
    .concat(proof.A)
    .concat(proof.B)
    .concat(proof.C)
    .concat(vk.S1)
    .concat(vk.S2);

  // Concatenate all 14 scalars (32 bytes each)
  const scalars = b32(frScalar(sQm))
    .concat(b32(frScalar(sQl)))
    .concat(b32(frScalar(sQr)))
    .concat(b32(frScalar(sQo)))
    .concat(b32(frScalar(sQc)))
    .concat(b32(frScalar(sZ)))
    .concat(b32(frScalar(sS3)))
    .concat(b32(frScalar(sT1)))
    .concat(b32(frScalar(sT2)))
    .concat(b32(frScalar(sT3)))
    .concat(b32(frScalar(sA)))
    .concat(b32(frScalar(sB)))
    .concat(b32(frScalar(sC)))
    .concat(b32(frScalar(sS1)))
    .concat(b32(frScalar(sS2)));

  // Single 14-point MSM computes F directly
  return op.EllipticCurve.scalarMulMulti(
    op.Ec.BLS12_381g1,
    points,
    scalars,
  ).toFixed({ length: 96 });
}

/**
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L386-L386
 */
export function calculateE(
  proof: PlonkProof,
  challenges: Challenges,
  r0: Uint256,
): bytes<96> {
  let e = frSub(
    frMul((challenges.v[1] as Uint256).asBigUint(), proof.eval_a.asBigUint()),
    r0.asBigUint(),
  );
  e = frAdd(
    e,
    frMul((challenges.v[2] as Uint256).asBigUint(), proof.eval_b.asBigUint()),
  );
  e = frAdd(
    e,
    frMul((challenges.v[3] as Uint256).asBigUint(), proof.eval_c.asBigUint()),
  );
  e = frAdd(
    e,
    frMul((challenges.v[4] as Uint256).asBigUint(), proof.eval_s1.asBigUint()),
  );
  e = frAdd(
    e,
    frMul((challenges.v[5] as Uint256).asBigUint(), proof.eval_s2.asBigUint()),
  );
  e = frAdd(e, frMul(challenges.u.asBigUint(), proof.eval_zw.asBigUint()));

  const res = g1TimesFr(G1_ONE.toFixed({ length: 96 }), e);
  return res;
}

/**
 * Final pairing check
 *
 * See https://github.com/iden3/snarkjs/blob/8ea294c099c9c10e095cf078ac41342388894668/src/plonk_verify.js#L402-L402
 */
export function isValidPairing(
  proof: PlonkProof,
  challenges: Challenges,
  vk: PlonkVerificationKey,
  E: bytes<96>,
  F: bytes<96>,
): boolean {
  let a1 = proof.Wxi;
  a1 = g1Add(a1, g1TimesFr(proof.Wxiw, challenges.u.asBigUint()));

  let b1 = g1TimesFr(proof.Wxi, challenges.xi.asBigUint());
  const s = frMul(
    frMul(challenges.u.asBigUint(), challenges.xi.asBigUint()),
    ROOT_OF_UNITY,
  );

  b1 = g1Add(b1, g1TimesFr(proof.Wxiw, s));
  b1 = g1Add(b1, F);
  b1 = g1Sub(b1, E);

  const res = op.EllipticCurve.pairingCheck(
    op.Ec.BLS12_381g1,
    g1Neg(a1).concat(b1),
    vk.X_2.concat(G2_ONE),
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
