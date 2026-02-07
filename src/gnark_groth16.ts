import type { Groth16Bn254Proof, Groth16Bn254VerificationKey } from "./groth16";

export function decodeGnarkBn254Proof(
  encodedProof: Uint8Array,
): Groth16Bn254Proof {
  if (encodedProof.length !== 256) {
    throw new Error(`Expected 256 proof bytes, got ${encodedProof.length}`);
  }

  // G1 points (piA, piC) are identical in both formats: [X(32), Y(32)]
  const piA = encodedProof.slice(0, 64);
  const piC = encodedProof.slice(192, 256);

  // G2 point (piB) needs Fq2 component reordering:
  //   Gnark:   [X.im, X.re, Y.im, Y.re]
  //   SnarkJS: [X.re, X.im, Y.re, Y.im]
  const piB = new Uint8Array(128);
  piB.set(encodedProof.slice(96, 128), 0); // X.re  → offset 0
  piB.set(encodedProof.slice(64, 96), 32); // X.im  → offset 32
  piB.set(encodedProof.slice(160, 192), 64); // Y.re  → offset 64
  piB.set(encodedProof.slice(128, 160), 96); // Y.im  → offset 96

  return { piA, piB, piC };
}

// ============================
// BN254 Field Arithmetic
// ============================

const P =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

function fqMod(a: bigint): bigint {
  return ((a % P) + P) % P;
}

function fqPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  base = fqMod(base);
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % P;
    exp >>= 1n;
    base = (base * base) % P;
  }
  return result;
}

function fqInv(a: bigint): bigint {
  return fqPow(a, P - 2n);
}

// p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4)
function fqSqrt(a: bigint): bigint | null {
  const s = fqPow(a, (P + 1n) / 4n);
  return (s * s) % P === fqMod(a) ? s : null;
}

// ============================
// Fq2 = Fq[u] / (u² + 1)
// Represented as [real, imaginary]
// ============================

type Fq2 = [bigint, bigint];

function fq2Add(a: Fq2, b: Fq2): Fq2 {
  return [fqMod(a[0] + b[0]), fqMod(a[1] + b[1])];
}

function fq2Mul(a: Fq2, b: Fq2): Fq2 {
  return [fqMod(a[0] * b[0] - a[1] * b[1]), fqMod(a[0] * b[1] + a[1] * b[0])];
}

function fq2Neg(a: Fq2): Fq2 {
  return [fqMod(-a[0]), fqMod(-a[1])];
}

function fq2Cube(a: Fq2): Fq2 {
  return fq2Mul(fq2Mul(a, a), a);
}

function fq2Sqrt(a: Fq2): Fq2 | null {
  const [a0, a1] = [fqMod(a[0]), fqMod(a[1])];

  if (a1 === 0n) {
    if (a0 === 0n) return [0n, 0n];
    const s = fqSqrt(a0);
    if (s !== null) return [s, 0n];
    const s2 = fqSqrt(fqMod(-a0));
    if (s2 !== null) return [0n, s2];
    return null;
  }

  // norm(a) = a0² + a1² in Fq
  const norm = fqMod(a0 * a0 + a1 * a1);
  const t = fqSqrt(norm);
  if (t === null) return null;

  const inv2 = fqInv(2n);

  // b0² = (a0 + t) / 2, falling back to (a0 - t) / 2
  let b0 = fqSqrt(fqMod((a0 + t) * inv2));
  if (b0 === null) {
    b0 = fqSqrt(fqMod((a0 - t) * inv2));
  }
  if (b0 === null) return null;

  // b1 = a1 / (2 * b0)
  const b1 = fqMod(a1 * fqInv(fqMod(2n * b0)));
  const result: Fq2 = [b0, b1];

  // Verify: (b0 + b1*u)² should equal a0 + a1*u
  const check = fq2Mul(result, result);
  if (fqMod(check[0]) !== a0 || fqMod(check[1]) !== a1) {
    return null; // should not happen for valid curve points
  }

  return result;
}

// Gnark/substrate-bn Fq2 ordering: compare imaginary first, then real
function fq2Gt(a: Fq2, b: Fq2): boolean {
  if (a[1] !== b[1]) return a[1] > b[1];
  return a[0] > b[0];
}

// ============================
// Byte helpers
// ============================

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) result = (result << 8n) | BigInt(b);
  return result;
}

function bigIntToBytes32(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

// ============================
// Gnark compressed point flags (2 MSBs)
// ============================

const FLAG_MASK = 0xc0;
const FLAG_POSITIVE = 0x80; // smaller y
const FLAG_NEGATIVE = 0xc0; // larger y

// ============================
// G1 decompression: 32 bytes → 64 bytes
// Curve: y² = x³ + 3
// ============================

function decompressG1(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 32) {
    throw new Error(`Invalid G1 compressed point: expected 32 bytes, got ${compressed.length}`);
  }

  const flag = compressed[0]! & FLAG_MASK;

  // Validate flag: must be either FLAG_POSITIVE (0x80) or FLAG_NEGATIVE (0xc0)
  if (flag !== FLAG_POSITIVE && flag !== FLAG_NEGATIVE) {
    throw new Error(`Invalid G1 point flag: 0x${flag.toString(16)}`);
  }

  const xBytes = new Uint8Array(compressed);
  xBytes[0]! &= ~FLAG_MASK;

  const x = bytesToBigInt(xBytes);
  const ySq = fqMod(fqPow(x, 3n) + 3n);
  let y = fqSqrt(ySq);
  if (y === null) throw new Error("Invalid G1 point");

  const negY = fqMod(-y);

  // Positive flag = smaller y, Negative flag = larger y
  if (y > negY) {
    if (flag === FLAG_POSITIVE) y = negY;
  } else {
    if (flag === FLAG_NEGATIVE) y = negY;
  }

  const result = new Uint8Array(64);
  result.set(bigIntToBytes32(x), 0);
  result.set(bigIntToBytes32(y), 32);
  return result;
}

// ============================
// G2 decompression: 64 bytes → 128 bytes
// Twist curve: y² = x³ + 3/(9+u)
// ============================

// b' = 3/(9+u) = 3*(9-u)/82
const INV_82 = fqInv(82n);
const B_TWIST: Fq2 = [
  fqMod(27n * INV_82), // real
  fqMod(-3n * INV_82), // imaginary
];

function decompressG2(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 64) {
    throw new Error(`Invalid G2 compressed point: expected 64 bytes, got ${compressed.length}`);
  }

  const flag = compressed[0]! & FLAG_MASK;

  // Validate flag: must be either FLAG_POSITIVE (0x80) or FLAG_NEGATIVE (0xc0)
  if (flag !== FLAG_POSITIVE && flag !== FLAG_NEGATIVE) {
    throw new Error(`Invalid G2 point flag: 0x${flag.toString(16)}`);
  }

  const xImBytes = new Uint8Array(compressed.slice(0, 32));
  xImBytes[0]! &= ~FLAG_MASK;

  // Gnark stores G2 compressed as [X.im(32), X.re(32)]
  const xIm = bytesToBigInt(xImBytes);
  const xRe = bytesToBigInt(compressed.slice(32, 64));
  const x: Fq2 = [xRe, xIm];

  // y² = x³ + b'
  const ySq = fq2Add(fq2Cube(x), B_TWIST);
  let y = fq2Sqrt(ySq);
  if (y === null) throw new Error("Invalid G2 point");

  const negY = fq2Neg(y);

  if (fq2Gt(y, negY)) {
    if (flag === FLAG_POSITIVE) y = negY;
  } else {
    if (flag === FLAG_NEGATIVE) y = negY;
  }

  // Output in SnarkJS ordering: [X.re, X.im, Y.re, Y.im]
  const result = new Uint8Array(128);
  result.set(bigIntToBytes32(x[0]), 0); // X.re
  result.set(bigIntToBytes32(x[1]), 32); // X.im
  result.set(bigIntToBytes32(y[0]), 64); // Y.re
  result.set(bigIntToBytes32(y[1]), 96); // Y.im
  return result;
}

// ============================
// VK conversion
// ============================

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

  // Minimum length: header up to and including num_k (292 bytes)
  if (vkBytes.length < 292) {
    throw new Error(
      `Invalid VK: expected at least 292 bytes, got ${vkBytes.length}`,
    );
  }

  const vk_alpha_1 = decompressG1(vkBytes.slice(0, 32));
  const vk_beta_2 = decompressG2(vkBytes.slice(64, 128));
  const vk_gamma_2 = decompressG2(vkBytes.slice(128, 192));
  const vk_delta_2 = decompressG2(vkBytes.slice(224, 288));

  // Parse as unsigned 32-bit big-endian to avoid signed integer issues with bitwise ops
  const num_k =
    vkBytes[288]! * 0x1000000 +
    vkBytes[289]! * 0x10000 +
    vkBytes[290]! * 0x100 +
    vkBytes[291]!;

  // Validate num_k (must be at least 1 for the constant term)
  if (num_k < 1) {
    throw new Error(`Invalid VK: num_k must be at least 1, got ${num_k}`);
  }

  // Validate that we have enough bytes for all IC points
  const requiredLength = 292 + 32 * num_k;
  if (vkBytes.length < requiredLength) {
    throw new Error(
      `Invalid VK: expected ${requiredLength} bytes for ${num_k} IC points, got ${vkBytes.length}`,
    );
  }

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
    nPublic: BigInt(num_k - 1), // IC[0] is the constant term
    ic: IC,
  };
}
