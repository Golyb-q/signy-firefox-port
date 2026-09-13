import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parsePkcs12, Pkcs12Error } from '../../extension/lib/pkcs12.js';

const fx = (p) => new Uint8Array(readFileSync(new URL('../fixtures/' + p, import.meta.url)));

test('parses legacy (BouncyCastle/Kalkan-style) RSA PKCS#12: 3DES key + RC2-40 certs + SHA1 MAC', async () => {
  const r = await parsePkcs12(fx('rsa/legacy-rc2-3des.p12'), 'Qwerty12');
  assert.equal(r.entries.length, 1);
  const e = r.entries[0];
  assert.equal(e.alias, 'test-rsa');
  assert.equal(e.key.type, 'RSA');
  assert.equal(e.cert.subjectCn, 'ТЕСТОВ ТЕСТ');
  assert.equal(e.cert.subjectAttr('2.5.4.5'), 'IIN123456789011');
});

test('parses modern OpenSSL 3 PKCS#12 (PBES2/AES-256, SHA-256 MAC)', async () => {
  const r = await parsePkcs12(fx('rsa/modern-aes.p12'), 'Qwerty12');
  assert.equal(r.entries.length, 1);
  assert.equal(r.entries[0].key.type, 'RSA');
});

test('wrong password is reported as WRONG_PASSWORD', async () => {
  await assert.rejects(parsePkcs12(fx('rsa/legacy-rc2-3des.p12'), 'nope'), (e) => e instanceof Pkcs12Error && e.code === 'WRONG_PASSWORD');
  await assert.rejects(parsePkcs12(fx('rsa/modern-aes.p12'), 'nope'), (e) => e instanceof Pkcs12Error && e.code === 'WRONG_PASSWORD');
});

test('garbage input is reported as BAD_FORMAT', async () => {
  await assert.rejects(parsePkcs12(new Uint8Array([1, 2, 3, 4]), 'x'), (e) => e.code === 'BAD_FORMAT');
});
