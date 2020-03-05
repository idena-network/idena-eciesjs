var crypto = require('crypto');

const ephemKeyLength = 65;
const ivLength = 16;
const macLength = 32;

function sha256(msg) {
  return crypto
    .createHash('sha256')
    .update(msg)
    .digest();
}

function hmacSha256(key, msg) {
  return crypto
    .createHmac('sha256', key)
    .update(msg)
    .digest();
}

function kdf(secret, outputLength) {
  let ctr = 1;
  let written = 0;
  let result = Buffer.from('');
  while (written < outputLength) {
    let ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr]);
    let hashResult = sha256(Buffer.concat([ctrs, secret]));
    result = Buffer.concat([result, hashResult]);
    written += 32;
    ctr += 1;
  }
  return result;
}

function aes128CtrEncrypt(iv, key, data) {
  var cipher = crypto.createCipheriv('aes-128-ctr', key, iv);
  var firstChunk = cipher.update(data);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function aes128CtrDecrypt(iv, key, data) {
  var cipher = crypto.createDecipheriv('aes-128-ctr', key, iv);
  var firstChunk = cipher.update(data);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  var res = 0;
  for (var i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i];
  }
  return res === 0;
}

function remove0x(hex) {
  if (hex.startsWith('0x') || hex.startsWith('0X')) {
    return hex.slice(2);
  }
  return hex;
}

exports.encrypt = function(publicKeyTo, msg) {
  const publicKey =
    typeof publicKeyTo === 'string'
      ? Buffer.from(remove0x(publicKeyTo), 'hex')
      : publicKeyTo;

  const data =
    typeof msg === 'string' ? Buffer.from(remove0x(msg), 'hex') : msg;

  let ephemPrivateKey = crypto.randomBytes(32);

  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(ephemPrivateKey);
  let ephemPublicKey = ecdh.getPublicKey();

  let px = ecdh.computeSecret(publicKey);
  let hash = kdf(px, 32);
  let iv = crypto.randomBytes(16);
  let encryptionKey = hash.slice(0, 16);
  let macKey = sha256(hash.slice(16));
  let ciphertext = aes128CtrEncrypt(iv, encryptionKey, data);
  let dataToMac = Buffer.concat([iv, ciphertext]);
  let HMAC = hmacSha256(macKey, dataToMac);
  return Buffer.concat([ephemPublicKey, iv, ciphertext, HMAC]);
};

exports.decrypt = function(key, data) {
  const privateKey =
    typeof key === 'string' ? Buffer.from(remove0x(key), 'hex') : key;
  const encrypted =
    typeof data === 'string' ? Buffer.from(remove0x(data), 'hex') : data;

  let metaLength = ephemKeyLength + ivLength + macLength;
  assert(
    encrypted.length > metaLength,
    'Invalid Ciphertext. Data is too small'
  );
  assert(encrypted[0] >= 2 && encrypted[0] <= 4, 'Not valid ciphertext.');

  // deserialise
  let ephemPublicKey = encrypted.slice(0, ephemKeyLength);
  let cipherTextLength = encrypted.length - metaLength;
  let iv = encrypted.slice(ephemKeyLength, ephemKeyLength + ivLength);
  let cipherAndIv = encrypted.slice(
    ephemKeyLength,
    ephemKeyLength + ivLength + cipherTextLength
  );
  let ciphertext = cipherAndIv.slice(ivLength);
  let msgMac = encrypted.slice(ephemKeyLength + ivLength + cipherTextLength);

  // derive private key
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(privateKey);
  let px = ecdh.computeSecret(ephemPublicKey);

  // create encryption key and mac key
  let hash = kdf(px, 32);
  let encryptionKey = hash.slice(0, 16);
  let macKey = sha256(hash.slice(16));

  // check HMAC
  let currentHMAC = hmacSha256(macKey, cipherAndIv);
  assert(equalConstTime(currentHMAC, msgMac), 'Incorrect MAC');

  // decrypt message
  return aes128CtrDecrypt(iv, encryptionKey, ciphertext);
};
