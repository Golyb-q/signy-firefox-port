import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { DES, cbcDecrypt, cbcEncrypt } from '../../extension/lib/cipher/des.js';
import { RC2, rc4 } from '../../extension/lib/cipher/rc2.js';
import { toHex, fromHex } from '../../extension/lib/util.js';

test('3DES-CBC matches node:crypto', () => {
  for (const len of [0, 1, 7, 8, 9, 100]) {
    const key = new Uint8Array(randomBytes(24));
    const iv = new Uint8Array(randomBytes(8));
    const pt = new Uint8Array(randomBytes(len));
    const c = createCipheriv('des-ede3-cbc', key, iv);
    const ct = new Uint8Array(Buffer.concat([c.update(pt), c.final()]));
    assert.equal(toHex(cbcEncrypt(new DES(key), iv, pt)), toHex(ct));
    assert.equal(toHex(cbcDecrypt(new DES(key), iv, ct)), toHex(pt));
  }
});

test('single DES known vector', () => {
  // FIPS 81 / classic example: key 133457799BBCDFF1, pt 0123456789ABCDEF -> 85E813540F0AB405
  const d = new DES(fromHex('133457799BBCDFF1'));
  assert.equal(toHex(d.encryptBlock(fromHex('0123456789ABCDEF'))), '85e813540f0ab405');
  assert.equal(toHex(d.decryptBlock(fromHex('85E813540F0AB405'))), '0123456789abcdef');
});

test('RC2 RFC 2268 vectors', () => {
  const v = [
    ['0000000000000000', 63, '0000000000000000', 'ebb773f993278eff'],
    ['ffffffffffffffff', 64, 'ffffffffffffffff', '278b27e42e2f0d49'],
    ['3000000000000000', 64, '1000000000000001', '30649edf9be7d2c2'],
    ['88', 64, '0000000000000000', '61a8a244adacccf0'],
    ['88bca90e90875a', 64, '0000000000000000', '6ccf4308974c267f'],
    ['88bca90e90875a7f0f79c384627bafb2', 64, '0000000000000000', '1a807d272bbe5db1'],
    ['88bca90e90875a7f0f79c384627bafb2', 128, '0000000000000000', '2269552ab0f85ca6'],
  ];
  for (const [k, bits, pt, ct] of v) {
    const c = new RC2(fromHex(k), bits);
    assert.equal(toHex(c.encryptBlock(fromHex(pt))), ct, k + '/' + bits);
    assert.equal(toHex(c.decryptBlock(fromHex(ct))), pt, k + '/' + bits + ' dec');
  }
});

test('RC2-40-CBC matches openssl (legacy provider)', () => {
  const key = fromHex('0011223344');
  const iv = fromHex('0001020304050607');
  const pt = new Uint8Array(randomBytes(37));
  const out = execFileSync('openssl', ['enc', '-rc2-40-cbc', '-provider', 'legacy', '-provider', 'default', '-K', toHex(key), '-iv', toHex(iv)], { input: pt });
  assert.equal(toHex(cbcEncrypt(new RC2(key, 40), iv, pt)), toHex(new Uint8Array(out)));
  assert.equal(toHex(cbcDecrypt(new RC2(key, 40), iv, new Uint8Array(out))), toHex(pt));
});

test('RC4 known vector', () => {
  // "Key" / "Plaintext" -> BBF316E8D940AF0AD3
  const ct = rc4(new TextEncoder().encode('Key'), new TextEncoder().encode('Plaintext'));
  assert.equal(toHex(ct), 'bbf316e8d940af0ad3');
});
