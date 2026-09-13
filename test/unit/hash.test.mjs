import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash as nodeHash, randomBytes } from 'node:crypto';
import { digest, hmac, pbkdf2 } from '../../extension/lib/hash/index.js';
import { toHex, fromHex, utf8Encode, reverseBytes } from '../../extension/lib/util.js';

test('SHA family matches node:crypto', () => {
  for (const len of [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1000, 4097]) {
    const data = new Uint8Array(randomBytes(len));
    assert.equal(toHex(digest('SHA-1', data)), nodeHash('sha1').update(data).digest('hex'), 'sha1 ' + len);
    assert.equal(toHex(digest('SHA-256', data)), nodeHash('sha256').update(data).digest('hex'), 'sha256 ' + len);
    assert.equal(toHex(digest('SHA-384', data)), nodeHash('sha384').update(data).digest('hex'), 'sha384 ' + len);
    assert.equal(toHex(digest('SHA-512', data)), nodeHash('sha512').update(data).digest('hex'), 'sha512 ' + len);
  }
});

test('HMAC and PBKDF2 match node:crypto', async () => {
  const { createHmac, pbkdf2Sync } = await import('node:crypto');
  const key = new Uint8Array(randomBytes(70));
  const data = new Uint8Array(randomBytes(200));
  assert.equal(toHex(hmac('SHA-256', key, data)), createHmac('sha256', key).update(data).digest('hex'));
  assert.equal(toHex(hmac('SHA-1', key, data)), createHmac('sha1', key).update(data).digest('hex'));
  const salt = new Uint8Array(randomBytes(16));
  assert.equal(toHex(pbkdf2('SHA-256', key, salt, 100, 40)), pbkdf2Sync(key, salt, 100, 40, 'sha256').toString('hex'));
});

test('GOST R 34.11-94 CryptoPro S-box (D-A) vectors', () => {
  const v = {
    '': '981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0',
    'This is message, length=32 bytes': '2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb',
    'Suppose the original message has length = 50 bytes': 'c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011',
    'message digest': 'bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0',
  };
  for (const [m, h] of Object.entries(v)) assert.equal(toHex(digest('GOSTR3411-94-CP', utf8Encode(m))), h, m);
});

test('GOST 34.311-95 (test S-box D-TEST) vectors', () => {
  const v = {
    '': 'ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d',
    'This is message, length=32 bytes': 'b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa',
    'Suppose the original message has length = 50 bytes': '471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208',
  };
  for (const [m, h] of Object.entries(v)) assert.equal(toHex(digest('GOST34311', utf8Encode(m))), h, m);
});

test('Streebog RFC 6986 vectors', () => {
  const m1 = utf8Encode('012345678901234567890123456789012345678901234567890123456789012');
  assert.equal(toHex(digest('GOST3411-2015-512', m1)),
    '1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48');
  assert.equal(toHex(digest('GOST3411-2015-256', m1)), '9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500');
  const m2 = reverseBytes(fromHex('fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1'));
  assert.equal(toHex(digest('GOST3411-2015-512', m2)),
    '1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28');
  assert.equal(toHex(digest('GOST3411-2015-256', m2)), '9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50');
});

test('Streebog streaming equals one-shot', async () => {
  const { Streebog } = await import('../../extension/lib/gost/streebog.js');
  const data = new Uint8Array(randomBytes(1000));
  const one = digest('GOST3411-2015-512', data);
  const s = new Streebog(512);
  for (let i = 0; i < data.length; i += 37) s.update(data.subarray(i, i + 37));
  assert.equal(toHex(s.digest()), toHex(one));
});
