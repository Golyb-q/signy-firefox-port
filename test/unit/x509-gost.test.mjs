import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Certificate } from '../../extension/lib/x509.js';
import { isOnCurve, multiply, generator, curveByOid } from '../../extension/lib/gost/ec.js';

const load = (p) => new Certificate(new Uint8Array(readFileSync(new URL('../fixtures/ca/' + p, import.meta.url))));

test('curve generators are on curve and have order q', () => {
  for (const oid of ['1.2.398.3.10.1.1.1.1.1', '1.2.643.2.2.35.2', '1.2.643.2.2.35.3', '1.2.398.3.10.1.1.2.2.1', '1.2.398.3.10.1.1.2.1.1']) {
    const c = curveByOid(oid);
    assert.ok(isOnCurve(c, generator(c)), c.name);
    // (q-1)*G == -G  -> x equal
    const P = multiply(c, generator(c), c.q - 1n);
    assert.equal(P.x, c.gx, c.name);
    assert.equal(P.y, c.p - c.gy, c.name);
  }
});

test('RSA NCA chain verifies', () => {
  const root = load('prod/rcarsa.cer');
  assert.ok(root.verifySignedBy(root), 'root self-signature');
  assert.ok(load('prod/ncarsa.cer').verifySignedBy(root));
  assert.ok(load('prod/ncarsa18.cer').verifySignedBy(root));
  const root20 = load('prod/rcarsa20.cer');
  assert.ok(root20.verifySignedBy(root20));
  assert.ok(load('prod/ncarsa22.cer').verifySignedBy(root20));
});

test('GOST 34.310-2004 NCA chain verifies (Kalkan conventions)', () => {
  const root = load('prod/rcagost.cer');
  assert.equal(root.keyFamily, 'GOST2004');
  assert.ok(root.verifySignedBy(root), 'root GOST self-signature');
  assert.ok(load('prod/ncagost.cer').verifySignedBy(root), 'ncagost');
  assert.ok(load('prod/ncagost18.cer').verifySignedBy(root), 'ncagost18');
});

test('GOST 34.10-2015 512 NCA chain verifies', () => {
  const root = load('prod/rcagost22.cer');
  assert.equal(root.keyFamily, 'GOST2015_512');
  assert.ok(root.verifySignedBy(root), 'root 2022 self-signature');
  assert.ok(load('prod/ncagost22.cer').verifySignedBy(root), 'ncagost22');
});

test('TEST CA chains verify', () => {
  const r1 = load('test/rcagosttest2018.cer');
  assert.ok(r1.verifySignedBy(r1));
  assert.ok(load('test/ncagosttest2018.cer').verifySignedBy(r1));
  const r2 = load('test/rcagosttest2022.cer');
  assert.ok(r2.verifySignedBy(r2));
  assert.ok(load('test/ncagosttest2022.cer').verifySignedBy(r2));
  const r3 = load('test/rcarsatest2018.cer');
  assert.ok(r3.verifySignedBy(r3));
  assert.ok(load('test/ncarsatest2018.cer').verifySignedBy(r3));
});

test('tampered certificate fails verification', () => {
  const root = load('prod/rcagost22.cer');
  const c = load('prod/ncagost22.cer');
  const raw = new Uint8Array(c.raw);
  raw[100] ^= 1;
  const bad = new Certificate(raw);
  assert.equal(bad.verifySignedBy(root), false);
});

test('Kalkan-style DN rendering', () => {
  const c = load('prod/ncagost.cer');
  assert.equal(c.subjectDnKalkan, 'C=KZ,L=АСТАНА,S=АСТАНА,O=РМК «МЕМЛЕКЕТТІК ТЕХНИКАЛЫҚ ҚЫЗМЕТ»,CN=ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST)');
});
