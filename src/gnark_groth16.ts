import * as nobleBn254 from "@noble/curves/bn254.js";
import type { Groth16Bn254Proof, Groth16Bn254VerificationKey } from "./groth16";

const bn254 = nobleBn254.bn254;
const { Fp, Fp2, Fr } = bn254.fields;
const G1Point = bn254.G1.Point;
const G2Point = bn254.G2.Point;

// BN254 curve order (subgroup order for both G1 and G2)
// Fr is the scalar field, and its order equals the subgroup order
const SUBGROUP_ORDER = Fr.ORDER;

const FLAG_MASK = 0xc0;
const FLAG_POSITIVE = 0x80; // smaller y
const FLAG_NEGATIVE = 0xc0; // larger y

const G2_B = Fp2.mulByB(Fp2.ONE);

/**
 * Maximum number of IC (input commitment) points allowed in a Gnark BN254 verification key.
 *
 * This limit is set to 1024 to prevent:
 * 1. Excessive memory consumption during VK parsing
 * 2. Potential DoS attacks with maliciously large VKs
 * 3. Transaction size limits on Algorand (16KB max)
 *
 * Each IC point is 32 bytes compressed, so 1024 points = 32KB which is already
 * over the Algorand limit. In practice, most circuits use < 100 public inputs.
 */
const MAX_GNARK_BN254_IC_POINTS = 1024;

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) result = (result << 8n) | BigInt(b);
  return result;
}

function assertFp(value: bigint, label: string): void {
  if (!Fp.isValid(value)) {
    throw new Error(`Invalid ${label}: out of range`);
  }
}

function readFp(bytes: Uint8Array, label: string): bigint {
  if (bytes.length !== Fp.BYTES) {
    throw new Error(
      `Invalid ${label} length: expected 32 bytes, got ${bytes.length}`,
    );
  }
  const value = bytesToBigIntBE(bytes);
  assertFp(value, label);
  return value;
}

function readFlag(bytes: Uint8Array, label: string): number {
  const flag = bytes[0]! & FLAG_MASK;
  if (flag !== FLAG_POSITIVE && flag !== FLAG_NEGATIVE) {
    throw new Error(`Invalid ${label} point flag: 0x${flag.toString(16)}`);
  }
  return flag;
}

function toSnarkjsG1Bytes(x: bigint, y: bigint): Uint8Array {
  const result = new Uint8Array(64);
  result.set(Fp.toBytes(x), 0);
  result.set(Fp.toBytes(y), 32);
  return result;
}

function toSnarkjsG2Bytes(
  x: { c0: bigint; c1: bigint },
  y: { c0: bigint; c1: bigint },
): Uint8Array {
  const result = new Uint8Array(128);
  result.set(Fp.toBytes(x.c0), 0); // X.re
  result.set(Fp.toBytes(x.c1), 32); // X.im
  result.set(Fp.toBytes(y.c0), 64); // Y.re
  result.set(Fp.toBytes(y.c1), 96); // Y.im
  return result;
}

function validateG1Affine(x: bigint, y: bigint): Uint8Array {
  const point = G1Point.fromAffine({ x, y });
  point.assertValidity();
  return toSnarkjsG1Bytes(x, y);
}

function validateG2Affine(
  x: { c0: bigint; c1: bigint },
  y: { c0: bigint; c1: bigint },
): Uint8Array {
  const point = G2Point.fromAffine({ x, y });
  point.assertValidity();

  // Validate subgroup membership: n * P should equal identity (point at infinity)
  // This is critical for security - points not in the correct subgroup can pass
  // curve equation checks but cause security vulnerabilities in pairing operations.
  //
  // We use (n-1) * P + P = O instead of n * P = O because noble-curves' multiply()
  // validates that scalar < field order, and n equals the field order.
  const multiplied = point.multiply(SUBGROUP_ORDER - 1n);
  const result = multiplied.add(point);
  if (!result.is0()) {
    throw new Error("Invalid G2 point: not in correct subgroup");
  }

  return toSnarkjsG2Bytes(x, y);
}

function fq2Gt(
  a: { c0: bigint; c1: bigint },
  b: { c0: bigint; c1: bigint },
): boolean {
  const { re: aRe, im: aIm } = Fp2.reim(a);
  const { re: bRe, im: bIm } = Fp2.reim(b);
  if (aIm !== bIm) return aIm > bIm;
  return aRe > bRe;
}

function chooseFpRoot(flag: number, y: bigint): bigint {
  const negY = Fp.neg(y);
  const smaller = y < negY ? y : negY;
  const larger = y < negY ? negY : y;
  return flag === FLAG_POSITIVE ? smaller : larger;
}

function chooseFp2Root(
  flag: number,
  y: { c0: bigint; c1: bigint },
): {
  c0: bigint;
  c1: bigint;
} {
  const negY = Fp2.neg(y);
  const isGreater = fq2Gt(y, negY);
  const smaller = isGreater ? negY : y;
  const larger = isGreater ? y : negY;
  return flag === FLAG_POSITIVE ? smaller : larger;
}

function decompressG1(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 32) {
    throw new Error(
      `Invalid G1 compressed point: expected 32 bytes, got ${compressed.length}`,
    );
  }

  const flag = readFlag(compressed, "G1");

  const xBytes = new Uint8Array(compressed);
  xBytes[0]! &= ~FLAG_MASK;
  const x = readFp(xBytes, "G1.x");

  let y: bigint;
  try {
    const ySq = Fp.add(Fp.mul(Fp.sqr(x), x), 3n);
    y = Fp.sqrt(ySq);
  } catch {
    throw new Error("Invalid G1 point");
  }

  const chosenY = chooseFpRoot(flag, y);
  return validateG1Affine(x, chosenY);
}

function decompressG2(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 64) {
    throw new Error(
      `Invalid G2 compressed point: expected 64 bytes, got ${compressed.length}`,
    );
  }

  const flag = readFlag(compressed, "G2");

  const xImBytes = new Uint8Array(compressed.slice(0, 32));
  xImBytes[0]! &= ~FLAG_MASK;

  const xIm = readFp(xImBytes, "G2.x.im");
  const xRe = readFp(compressed.slice(32, 64), "G2.x.re");
  const x = { c0: xRe, c1: xIm };

  let y: { c0: bigint; c1: bigint };
  try {
    const ySq = Fp2.add(Fp2.mul(Fp2.sqr(x), x), G2_B);
    y = Fp2.sqrt(ySq);
  } catch {
    throw new Error("Invalid G2 point");
  }

  const chosenY = chooseFp2Root(flag, y);
  return validateG2Affine(x, chosenY);
}

function parseG1Uncompressed(bytes: Uint8Array, label: string): Uint8Array {
  if (bytes.length !== 64) {
    throw new Error(`Invalid ${label}: expected 64 bytes, got ${bytes.length}`);
  }
  const x = readFp(bytes.slice(0, 32), `${label}.x`);
  const y = readFp(bytes.slice(32, 64), `${label}.y`);
  return validateG1Affine(x, y);
}

function parseG2Uncompressed(bytes: Uint8Array, label: string): Uint8Array {
  if (bytes.length !== 128) {
    throw new Error(
      `Invalid ${label}: expected 128 bytes, got ${bytes.length}`,
    );
  }

  const xIm = readFp(bytes.slice(0, 32), `${label}.x.im`);
  const xRe = readFp(bytes.slice(32, 64), `${label}.x.re`);
  const yIm = readFp(bytes.slice(64, 96), `${label}.y.im`);
  const yRe = readFp(bytes.slice(96, 128), `${label}.y.re`);

  const x = { c0: xRe, c1: xIm };
  const y = { c0: yRe, c1: yIm };
  return validateG2Affine(x, y);
}

export function decodeGnarkBn254Proof(
  encodedProof: Uint8Array,
): Groth16Bn254Proof {
  if (encodedProof.length !== 256) {
    throw new Error(`Expected 256 proof bytes, got ${encodedProof.length}`);
  }

  const piA = parseG1Uncompressed(encodedProof.slice(0, 64), "proof.piA");
  const piB = parseG2Uncompressed(encodedProof.slice(64, 192), "proof.piB");
  const piC = parseG1Uncompressed(encodedProof.slice(192, 256), "proof.piC");

  return { piA, piB, piC };
}

export function decodeGnarkBn254Vk(
  vkBytes: Uint8Array,
): Groth16Bn254VerificationKey {
  // [0..32]    G1 Alpha compressed
  // [32..64]   G1 Beta compressed (unused)
  // [64..128]  G2 Beta compressed
  // [128..192] G2 Gamma compressed
  // [192..224] G1 Delta compressed (unused)
  // [224..288] G2 Delta compressed
  // [288..292] num_k (u32 big-endian)
  // [292..]    K[] compressed G1 points (32 bytes each)

  if (vkBytes.length < 292) {
    throw new Error(
      `Invalid VK: expected at least 292 bytes, got ${vkBytes.length}`,
    );
  }

  const num_k = new DataView(
    vkBytes.buffer,
    vkBytes.byteOffset + 288,
    4,
  ).getUint32(0, false);

  if (num_k < 1) {
    throw new Error(`Invalid VK: num_k must be at least 1, got ${num_k}`);
  }

  if (num_k > MAX_GNARK_BN254_IC_POINTS) {
    throw new Error(
      `Invalid VK: num_k must be <= ${MAX_GNARK_BN254_IC_POINTS}, got ${num_k}`,
    );
  }

  const requiredLength = 292 + 32 * num_k;
  if (vkBytes.length < requiredLength) {
    throw new Error(
      `Invalid VK: expected at least ${requiredLength} bytes, got ${vkBytes.length}`,
    );
  }

  const vk_alpha_1 = decompressG1(vkBytes.slice(0, 32));
  const vk_beta_2 = decompressG2(vkBytes.slice(64, 128));
  const vk_gamma_2 = decompressG2(vkBytes.slice(128, 192));
  const vk_delta_2 = decompressG2(vkBytes.slice(224, 288));

  const IC: Uint8Array[] = [];
  let offset = 292;
  for (let i = 0; i < num_k; i++) {
    IC.push(decompressG1(vkBytes.slice(offset, offset + 32)));
    offset += 32;
  }

  return {
    vkAlpha_1: vk_alpha_1,
    vkBeta_2: vk_beta_2,
    vkGamma_2: vk_gamma_2,
    vkDelta_2: vk_delta_2,
    nPublic: BigInt(num_k - 1),
    ic: IC,
  };
}
