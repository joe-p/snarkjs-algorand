import {
  type bytes,
  op,
  BigUint,
  Bytes,
  type biguint,
  log,
} from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

/**
 * BN254 curve-specific constants and utilities
 */

/** BN254 scalar field modulus (Fr), 32-byte big-endian */
export const BN254_SCALAR_MODULUS = BigUint(
  Bytes.fromHex(
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  ),
);

/**
 * BN254_SCALAR_MODULUS - 1, used for point negation
 */
export const R_MINUS_1 = BigUint(
  Bytes.fromHex(
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
  ),
);

/**
 * Reduce to canonical form in the scalar field Fr.
 * Computes a mod r where r is the BN254 scalar field modulus.
 * Ensures the result is in the range [0, r-1].
 */
export function frScalar(a: biguint): biguint {
  return a % BN254_SCALAR_MODULUS;
}

/**
 * Convert a big unsigned integer to 32-byte big-endian representation.
 * Used for serializing field elements.
 */
export function b32(a: biguint): bytes<32> {
  return new Uint256(a).bytes.toFixed({ length: 32 });
}

/**
 * Debug logging helper
 */
export function debugLog(name: string, value: bytes): void {
  log(name);
  log(value);
}

/**
 * Scalar multiplication on the BN254 G1 group.
 * Computes s * P where P is a G1 point and s is a scalar in Fr.
 * Returns the result as a 64-byte uncompressed G1 point.
 */
export function g1TimesFr(p: bytes<64>, s: biguint): bytes<64> {
  return op.EllipticCurve.scalarMul(op.Ec.BN254g1, p, Bytes(s)).toFixed({
    length: 64,
  });
}

/**
 * Point addition on the BN254 G1 group.
 * Computes P1 + P2 where P1 and P2 are G1 points.
 * Returns the result as a 64-byte uncompressed G1 point.
 */
export function g1Add(p1: bytes<64>, p2: bytes<64>): bytes<64> {
  return op.EllipticCurve.add(op.Ec.BN254g1, p1, p2).toFixed({ length: 64 });
}

/**
 * Point negation on the BN254 G1 group.
 * Computes -P where P is a G1 point by multiplying by (r-1) where r is the scalar field modulus.
 * This is equivalent to negating the y-coordinate in affine representation.
 */
export function g1Neg(p: bytes<64>): bytes<64> {
  return g1TimesFr(p, R_MINUS_1);
}

/**
 * Check if a value is in the scalar field Fr
 */
export function inField(value: Uint256): boolean {
  return value.asBigUint() < BN254_SCALAR_MODULUS;
}

export type PublicSignals = Uint256[];
