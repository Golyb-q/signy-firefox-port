// GOST 34.310-2004 / GOST R 34.10-2001 / GOST 34.10-2015 (2012) digital signatures,
// following Kalkan (BouncyCastle ECGOST3410Signer + JDKGOST3410Signer/EcGost2015SignatureSpi) conventions:
//  * e = hash interpreted as a little-endian integer (BigInteger(1, reverse(hash)))
//  * signature bytes = reverse( s_BE || r_BE )  (i.e. r little-endian, then s little-endian)
//  * public key = OCTET STRING( x_LE || y_LE )
//  * verification also accepts RFC 4491 order s_BE || r_BE (Kalkan does the same fallback)
import { multiply, mulAdd, isOnCurve, generator, INFINITY } from './ec.js';
import {
  mod, modInv, reverseBytes, bytesToBigInt, bytesToBigIntLE, bigIntToBytes, bigIntToBytesLE,
  randomBigIntBelow, concat,
} from '../util.js';

function hashToE(hash, q) {
  let e = mod(bytesToBigInt(reverseBytes(hash)), q);
  if (e === 0n) e = 1n;
  return e;
}

/** Returns { r, s } as BigInt. `k` may be supplied for deterministic tests. */
export function signHash(curve, d, hash, k) {
  const { q } = curve;
  const e = hashToE(hash, q);
  for (;;) {
    const kk = k ?? randomBigIntBelow(q);
    const C = multiply(curve, generator(curve), kk);
    const r = mod(C.x, q);
    if (r === 0n) {
      if (k) throw new Error('bad k');
      continue;
    }
    const s = mod(r * d + kk * e, q);
    if (s === 0n) {
      if (k) throw new Error('bad k');
      continue;
    }
    return { r, s };
  }
}

export function verifyHash(curve, Q, hash, r, s) {
  const { q } = curve;
  if (r <= 0n || r >= q || s <= 0n || s >= q) return false;
  const e = hashToE(hash, q);
  const v = modInv(e, q);
  const z1 = mod(s * v, q);
  const z2 = mod(-r * v, q);
  const C = mulAdd(curve, z1, Q, z2);
  if (C === INFINITY) return false;
  return mod(C.x, q) === r;
}

/** Kalkan wire format: reverse(s_BE(n) || r_BE(n)). */
export function encodeSignature(curve, { r, s }) {
  const n = curve.bytes;
  return reverseBytes(concat(bigIntToBytes(s, n), bigIntToBytes(r, n)));
}

/** Decode signature bytes; returns candidate (r,s) pairs in the order Kalkan tries them. */
export function decodeSignatureCandidates(sig) {
  const half = sig.length / 2;
  const rev = reverseBytes(sig);
  return [
    // Kalkan native: after reversing -> s_BE || r_BE
    { s: bytesToBigInt(rev.subarray(0, half)), r: bytesToBigInt(rev.subarray(half)) },
    // RFC 4491: s_BE || r_BE
    { s: bytesToBigInt(sig.subarray(0, half)), r: bytesToBigInt(sig.subarray(half)) },
  ];
}

export function verifySignature(curve, Q, hash, sig) {
  for (const { r, s } of decodeSignatureCandidates(sig)) {
    if (verifyHash(curve, Q, hash, r, s)) return true;
  }
  return false;
}

/** Decode public key point from the OCTET STRING content (x_LE || y_LE). Falls back to BE if LE is not on curve. */
export function decodePublicPoint(curve, bytes) {
  const n = bytes.length / 2;
  if (!Number.isInteger(n) || n === 0) throw new Error('bad GOST public key length ' + bytes.length);
  const le = { x: bytesToBigIntLE(bytes.subarray(0, n)), y: bytesToBigIntLE(bytes.subarray(n)) };
  if (isOnCurve(curve, le)) return le;
  const be = { x: bytesToBigInt(bytes.subarray(0, n)), y: bytesToBigInt(bytes.subarray(n)) };
  if (isOnCurve(curve, be)) return be;
  throw new Error('GOST public key point is not on the curve ' + curve.name);
}

export function encodePublicPoint(curve, P) {
  return concat(bigIntToBytesLE(P.x, curve.bytes), bigIntToBytesLE(P.y, curve.bytes));
}

export function publicFromPrivate(curve, d) {
  return multiply(curve, generator(curve), d);
}
