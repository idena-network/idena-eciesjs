const assert = require('assert');
const crypto = require('crypto');
const { encrypt, decrypt } = require('..');

describe('encrypt  decrypt', () => {
  it('should encrypt and decrypt strings', () => {
    let privateKey = Buffer.from(
      'afd4fee14dd189f3191ac044a72e9da661656ff89bb7d52e33b56681aa465547',
      'hex'
    );
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(privateKey);

    console.log(privateKey.toString('hex'));

    const cases = [
      '11',
      '112233',
      '8987766554433211',
      '9d6669e9519c2958dbc69837e890b527b0a3328ac54ae170e97ff2242f45'
    ];

    cases.forEach((data, idx) => {
      const encrypted = encrypt(ecdh.getPublicKey(), data);
      const decrypted = decrypt(privateKey, encrypted);

      console.log(encrypted.toString('hex'));

      assert.equal(
        decrypted.toString('hex'),
        data,
        'Failed test case #' + (idx + 1)
      );
    });
  });

  it('should encrypt and decrypt Buffers', () => {
    let privateKey = crypto.randomBytes(32);
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(privateKey);

    const cases = [
      Buffer.from([0x1]),
      Buffer.from([0x1, 0x1, 0x2, 0x3, 0x4]),
      Buffer.from([0x1, 0x0, 0x2, 0x3, 0x4, 0x1, 0x1, 0x2, 0x3, 0x4])
    ];

    cases.forEach((data, idx) => {
      const encrypted = encrypt(ecdh.getPublicKey(), data);
      const decrypted = decrypt(privateKey, encrypted);

      assert.deepEqual(decrypted, data, 'Failed test case #' + (idx + 1));
    });
  });
});
