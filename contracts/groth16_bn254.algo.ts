import {
  type bytes,
  op,
  type uint64,
  Bytes,
  assert,
  TemplateVar,
} from "@algorandfoundation/algorand-typescript";
import { decodeArc4 } from "@algorandfoundation/algorand-typescript/arc4";
import {
  frScalar,
  b32,
  debugLog,
  g1Add,
  g1Neg,
  inField,
  type PublicSignals,
} from "./bn254_common.algo";

/**
 * Groth16 BN254 verifier for (SNARKJS-compatible)
 *
 * This verifier implements the Groth16 zero-knowledge proof system verification
 * as described in https://eprint.iacr.org/2016/260.pdf
 *
 * The verification process:
 * 1) Compute cpub = IC[0] + Σ(publicSignals[i] * IC[i+1]) via multi-exponentiation
 * 2) Validate proof points are in correct subgroups
 * 3) Perform pairing check: e(-pi_a, pi_b) * e(cpub, vk_gamma_2) * e(pi_c, vk_delta_2) * e(vk_alpha_1, vk_beta_2) = 1
 *
 * Field operations are over BN254 Fr; commitments are on G1/G2.
 */

/**
 * Groth16 BN254 proof structure
 * Contains three commitments that prove knowledge of a satisfying assignment
 */
export type Groth16Bn254Proof = {
  /** Prover's first commitment (G1 point) */
  pi_a: bytes<64>;
  /** Prover's second commitment (G2 point) */
  pi_b: bytes<128>;
  /** Prover's third commitment (G1 point) */
  pi_c: bytes<64>;
};

/**
 * Groth16 BN254 verification key structure
 * Contains preprocessed circuit information for efficient verification
 */
export type Groth16Bn254VerificationKey = {
  /** Alpha parameter in G1 */
  vk_alpha_1: bytes<64>;
  /** Beta parameter in G2 */
  vk_beta_2: bytes<128>;
  /** Gamma parameter in G2 */
  vk_gamma_2: bytes<128>;
  /** Delta parameter in G2 */
  vk_delta_2: bytes<128>;
  /** Number of public inputs */
  nPublic: uint64;
  /** IC array: IC[0] is the constant term, IC[1..nPublic] correspond to public inputs */
  IC: bytes<64>[];
};

/**
 * Check if a G1 point is in the correct subgroup
 */
function g1GroupCheck(p: bytes<64>): boolean {
  return op.EllipticCurve.subgroupCheck(op.Ec.BN254g1, p);
}

/**
 * Check if a G2 point is in the correct subgroup
 */
function g2GroupCheck(p: bytes<128>): boolean {
  return op.EllipticCurve.subgroupCheck(op.Ec.BN254g2, p);
}

/**
 * Validate that all proof points are in correct subgroups
 */
function assertProofInSubgroup(proof: Groth16Bn254Proof): void {
  assert(g1GroupCheck(proof.pi_a), "pi_a not in G1");
  assert(g2GroupCheck(proof.pi_b), "pi_b not in G2");
  assert(g1GroupCheck(proof.pi_c), "pi_c not in G1");
}

/**
 * Validate that all public signals are in the scalar field Fr
 */
function assertSignalsInField(
  vk: Groth16Bn254VerificationKey,
  signals: PublicSignals,
): void {
  assert(signals.length === vk.nPublic, "Invalid number of public inputs");

  for (const signal of signals) {
    assert(inField(signal), "public signal not in Fr");
  }
}

/**
 * Validate proof inputs (subgroup membership and field membership)
 */
export function validateInput(
  vk: Groth16Bn254VerificationKey,
  signals: PublicSignals,
  proof: Groth16Bn254Proof,
): void {
  assertProofInSubgroup(proof);
  assertSignalsInField(vk, signals);
}

/**
 * Compute the linear combination of IC points with public signals
 * cpub = IC[0] + Σ(publicSignals[i] * IC[i+1])
 *
 * This uses multi-scalar multiplication for efficiency.
 */
function computeCpub(
  vk: Groth16Bn254VerificationKey,
  signals: PublicSignals,
): bytes<64> {
  // IC array contains (nPublic + 1) G1 points
  // IC[0] is the constant term, IC[1..nPublic] correspond to public inputs

  if (signals.length === 0) {
    // No public inputs, just return IC[0]
    return vk.IC[0] as bytes<64>;
  }

  // Concatenate IC[1..nPublic] for multi-scalar multiplication
  let icPoints = Bytes();
  for (let i: uint64 = 1; i <= signals.length; i++) {
    icPoints = op.concat(icPoints, vk.IC[i] as bytes<64>);
  }

  // Build scalars array from public signals
  let scalars = Bytes();
  for (const signal of signals) {
    scalars = op.concat(scalars, b32(frScalar(signal.asBigUint())));
  }

  // Compute Σ(publicSignals[i] * IC[i+1])
  let cpub = op.EllipticCurve.scalarMulMulti(
    op.Ec.BN254g1,
    icPoints,
    scalars,
  ).toFixed({ length: 64 });

  // Add IC[0]
  cpub = g1Add(cpub, vk.IC[0] as bytes<64>);

  return cpub;
}

/**
 * Main Groth16 BN254 verification function
 *
 * Verifies a Groth16 proof by checking the pairing equation:
 * e(-pi_a, pi_b) * e(cpub, vk_gamma_2) * e(pi_c, vk_delta_2) * e(vk_alpha_1, vk_beta_2) = 1
 *
 * Where cpub = IC[0] + Σ(publicSignals[i] * IC[i+1])
 */
export function verify(
  vk: Groth16Bn254VerificationKey,
  signals: PublicSignals,
  proof: Groth16Bn254Proof,
): boolean {
  // Validate inputs
  validateInput(vk, signals, proof);

  // Compute linear combination of IC points with public inputs
  const cpub = computeCpub(vk, signals);

  // Perform pairing check: e(-pi_a, pi_b) * e(cpub, vk_gamma_2) * e(pi_c, vk_delta_2) * e(vk_alpha_1, vk_beta_2) = 1
  // We use the multi-pairing check which is more efficient
  // Concatenate G1 points: -pi_a || cpub || pi_c || vk_alpha_1
  const negPiA = g1Neg(proof.pi_a);
  let g1Points = op.concat(negPiA, cpub);
  g1Points = op.concat(g1Points, proof.pi_c);
  g1Points = op.concat(g1Points, vk.vk_alpha_1);

  // Concatenate G2 points: pi_b || vk_gamma_2 || vk_delta_2 || vk_beta_2
  let g2Points = op.concat(proof.pi_b, vk.vk_gamma_2);
  g2Points = op.concat(g2Points, vk.vk_delta_2);
  g2Points = op.concat(g2Points, vk.vk_beta_2);

  // Final pairing check
  const res = op.EllipticCurve.pairingCheck(op.Ec.BN254g1, g1Points, g2Points);

  return res;
}

/**
 * Main Groth16 BN254 verification function with debug logging
 */
export function verifyWithLogs(
  vk: Groth16Bn254VerificationKey,
  signals: PublicSignals,
  proof: Groth16Bn254Proof,
): boolean {
  // Validate inputs
  validateInput(vk, signals, proof);

  // Compute linear combination of IC points with public inputs
  const cpub = computeCpub(vk, signals);
  debugLog("cpub", cpub);

  // Perform pairing check
  debugLog("pi_a", proof.pi_a);
  debugLog("pi_b", proof.pi_b);
  debugLog("pi_c", proof.pi_c);

  // Concatenate G1 points: -pi_a || cpub || pi_c || vk_alpha_1
  const negPiA = g1Neg(proof.pi_a);
  let g1Points = op.concat(negPiA, cpub);
  g1Points = op.concat(g1Points, proof.pi_c);
  g1Points = op.concat(g1Points, vk.vk_alpha_1);

  // Concatenate G2 points: pi_b || vk_gamma_2 || vk_delta_2 || vk_beta_2
  let g2Points = op.concat(proof.pi_b, vk.vk_gamma_2);
  g2Points = op.concat(g2Points, vk.vk_delta_2);
  g2Points = op.concat(g2Points, vk.vk_beta_2);

  // Final pairing check
  const res = op.EllipticCurve.pairingCheck(op.Ec.BN254g1, g1Points, g2Points);

  debugLog("pairing result", res ? Bytes.fromHex("01") : Bytes.fromHex("00"));

  return res;
}

/**
 * Verify proof using verification key from template variable
 */
export function verifyFromTemplate(
  signals: PublicSignals,
  proof: Groth16Bn254Proof,
): boolean {
  const vkBytes = TemplateVar<bytes>("VERIFICATION_KEY");

  return verify(
    decodeArc4<Groth16Bn254VerificationKey>(vkBytes),
    signals,
    proof,
  );
}

/**
 * Verify proof using verification key from template variable with debug logging
 */
export function verifyFromTemplateWithLogs(
  signals: PublicSignals,
  proof: Groth16Bn254Proof,
): boolean {
  const vkBytes = TemplateVar<bytes>("VERIFICATION_KEY");

  return verifyWithLogs(
    decodeArc4<Groth16Bn254VerificationKey>(vkBytes),
    signals,
    proof,
  );
}

/**
 * Encoding & Endianness summary
 * - Field elements: 32-byte big-endian
 * - G1: 64-byte uncompressed x||y (BE)
 * - G2: 128-byte uncompressed x.c0||x.c1||y.c0||y.c1 (each 32-byte BE)
 * - IC array: concatenated 64-byte G1 points
 */
