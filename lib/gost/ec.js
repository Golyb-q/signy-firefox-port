// Elliptic curve arithmetic over prime fields (short Weierstrass y^2 = x^3 + ax + b) using BigInt.
// Jacobian coordinates, windowed scalar multiplication.
import { mod, modInv } from '../util.js';

const h = (s) => BigInt('0x' + s);

function curve(name, p, a, b, q, x, y, bytes) {
  return { name, p, a, b, q, gx: x, gy: y, bytes };
}

const CRYPTOPRO_A = curve('GostR3410-2001-CryptoPro-A',
  BigInt('115792089237316195423570985008687907853269984665640564039457584007913129639319'),
  BigInt('115792089237316195423570985008687907853269984665640564039457584007913129639316'),
  166n,
  BigInt('115792089237316195423570985008687907853073762908499243225378155805079068850323'),
  1n,
  BigInt('64033881142927202683649881450433473985931760268884941288852745803908878638612'),
  32);

const CRYPTOPRO_B = curve('GostR3410-2001-CryptoPro-B',
  BigInt('57896044618658097711785492504343953926634992332820282019728792003956564823193'),
  BigInt('57896044618658097711785492504343953926634992332820282019728792003956564823190'),
  BigInt('28091019353058090096996979000309560759124368558014865957655842872397301267595'),
  BigInt('57896044618658097711785492504343953927102133160255826820068844496087732066703'),
  1n,
  BigInt('28792665814854611296992347458380284135028636778229113005756334730996303888124'),
  32);

const CRYPTOPRO_C = curve('GostR3410-2001-CryptoPro-C',
  BigInt('70390085352083305199547718019018437841079516630045180471284346843705633502619'),
  BigInt('70390085352083305199547718019018437841079516630045180471284346843705633502616'),
  32858n,
  BigInt('70390085352083305199547718019018437840920882647164081035322601458352298396601'),
  0n,
  BigInt('29818893917731240733471273240314769927240550812383695689146495261604565990247'),
  32);

const TC26_512_A = curve('Gost3410-2015-512-ParamSetA',
  h('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7'),
  h('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4'),
  h('E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760'),
  h('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275'),
  3n,
  h('7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4'),
  64);

const TC26_256_A = curve('Gost3410-2015-256-ParamSetA',
  h('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97'),
  h('C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335'),
  h('295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513'),
  h('400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67'),
  h('91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28'),
  h('32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C'),
  32);

/** Curve parameter-set OIDs -> curves (Kazakhstan + Russian aliases). */
export const CURVES = {
  '1.2.398.3.10.1.1.1.1.1': CRYPTOPRO_A, // gost34310_2004_PKIGOVKZ_A
  '1.2.643.2.2.35.1': CRYPTOPRO_A,
  '1.2.643.2.2.36.0': CRYPTOPRO_A, // XchA
  '1.2.643.2.2.35.2': CRYPTOPRO_B,
  '1.2.643.2.2.35.3': CRYPTOPRO_C,
  '1.2.643.2.2.36.1': CRYPTOPRO_C, // XchB
  '1.2.398.3.10.1.1.2.2.1': TC26_512_A, // gost3410_2015_512_ParamSetA
  '1.2.643.7.1.2.1.2.1': TC26_512_A,
  '1.2.398.3.10.1.1.2.1.1': TC26_256_A, // gost3410_2015_256_ParamSetA
  '1.2.643.7.1.2.1.1.1': TC26_256_A,
};

export function curveByOid(oid) {
  const c = CURVES[oid];
  if (!c) throw new Error('Unsupported GOST curve parameters ' + oid);
  return c;
}

export const INFINITY = null;

// Jacobian point: [X, Y, Z]; affine (x, y) = (X/Z^2, Y/Z^3). Z = 0n -> infinity.

function jDouble(c, P) {
  const [X, Y, Z] = P;
  if (Z === 0n || Y === 0n) return [1n, 1n, 0n];
  const p = c.p;
  const YY = (Y * Y) % p;
  const S = (4n * X * YY) % p;
  const ZZ = (Z * Z) % p;
  const M = (3n * X * X + c.a * ZZ * ZZ) % p;
  const X3 = mod(M * M - 2n * S, p);
  const Y3 = mod(M * (S - X3) - 8n * YY * YY, p);
  const Z3 = (2n * Y * Z) % p;
  return [X3, Y3, Z3];
}

function jAdd(c, P, Q) {
  if (P[2] === 0n) return Q;
  if (Q[2] === 0n) return P;
  const p = c.p;
  const [X1, Y1, Z1] = P;
  const [X2, Y2, Z2] = Q;
  const Z1Z1 = (Z1 * Z1) % p;
  const Z2Z2 = (Z2 * Z2) % p;
  const U1 = (X1 * Z2Z2) % p;
  const U2 = (X2 * Z1Z1) % p;
  const S1 = (Y1 * Z2 * Z2Z2) % p;
  const S2 = (Y2 * Z1 * Z1Z1) % p;
  if (U1 === U2) {
    if (S1 !== S2) return [1n, 1n, 0n];
    return jDouble(c, P);
  }
  const H = mod(U2 - U1, p);
  const R = mod(S2 - S1, p);
  const HH = (H * H) % p;
  const HHH = (H * HH) % p;
  const V = (U1 * HH) % p;
  const X3 = mod(R * R - HHH - 2n * V, p);
  const Y3 = mod(R * (V - X3) - S1 * HHH, p);
  const Z3 = (Z1 * Z2 * H) % p;
  return [X3, Y3, Z3];
}

function toAffine(c, P) {
  if (P[2] === 0n) return INFINITY;
  const zi = modInv(P[2], c.p);
  const zi2 = (zi * zi) % c.p;
  return { x: (P[0] * zi2) % c.p, y: (P[1] * zi2 * zi) % c.p };
}

/** Scalar multiplication k*P for affine P, returns affine point or null (infinity). */
export function multiply(c, P, k) {
  if (P === INFINITY) return INFINITY;
  k = mod(k, c.q);
  if (k === 0n) return INFINITY;
  // 4-bit fixed window
  const base = [P.x, P.y, 1n];
  const table = [[1n, 1n, 0n], base];
  for (let i = 2; i < 16; i++) table.push(jAdd(c, table[i - 1], base));
  let R = [1n, 1n, 0n];
  const hex = k.toString(16);
  for (let i = 0; i < hex.length; i++) {
    R = jDouble(c, jDouble(c, jDouble(c, jDouble(c, R))));
    const w = parseInt(hex[i], 16);
    if (w) R = jAdd(c, R, table[w]);
  }
  return toAffine(c, R);
}

export function add(c, P, Q) {
  if (P === INFINITY) return Q;
  if (Q === INFINITY) return P;
  return toAffine(c, jAdd(c, [P.x, P.y, 1n], [Q.x, Q.y, 1n]));
}

/** u1*G + u2*Q */
export function mulAdd(c, u1, Q, u2) {
  return add(c, multiply(c, { x: c.gx, y: c.gy }, u1), multiply(c, Q, u2));
}

export function isOnCurve(c, P) {
  if (P === INFINITY) return false;
  const { p } = c;
  if (P.x < 0n || P.x >= p || P.y < 0n || P.y >= p) return false;
  return mod(P.y * P.y - (P.x * P.x * P.x + c.a * P.x + c.b), p) === 0n;
}

export function generator(c) {
  return { x: c.gx, y: c.gy };
}
