// copied and modified from o1js: https://github.com/o1-labs/o1js/tree/main/src/examples/crypto/rsa
import assert from 'node:assert';
import { Bigint2048, rsaVerify65537, rsaSign } from './rsa.ts';
import { generateRsaKeys65537, randomPrime } from './utils.ts';
import { it, describe } from 'node:test';
import { SHA2 } from '../dynamic/sha2.ts';

describe('RSA65537 verification tests', () => {
  it('should accept RSA signature (5 iterations)', async () => {
    const message = SHA2.hash(256, 'hello there!');

    for (let i = 0; i < 5; i++) {
      const params = generateRsaKeys65537();

      const signature = Bigint2048.from(rsaSign(message, params));
      const modulus = Bigint2048.from(params.n);

      rsaVerify65537(message, signature, modulus);
    }
  });

  it('should reject RSA signature with non-compliant modulus', async () => {
    const message = SHA2.hash(256, 'hello!');
    const params = generateRsaKeys65537();

    const signature = Bigint2048.from(rsaSign(message, params));
    const modulus = Bigint2048.from(randomPrime(2048)); // Tamper with modulus

    assert.throws(() => rsaVerify65537(message, signature, modulus));
  });

  it('should reject RSA signature with non-compliant input', async () => {
    let message = SHA2.hash(256, 'hello!');
    const params = generateRsaKeys65537();

    const signature = Bigint2048.from(rsaSign(message, params));

    message = SHA2.hash(256, 'hello!*'); // Tamper with message
    const modulus = Bigint2048.from(params.n);

    assert.throws(() => rsaVerify65537(message, signature, modulus));
  });

  it('should reject non compliant RSA signature: false private key', async () => {
    let message = SHA2.hash(256, 'hello!');
    const params = generateRsaKeys65537();

    const signature = Bigint2048.from(
      rsaSign(message, { d: params.e, n: params.n })
    ); // Tamper with private key
    const modulus = Bigint2048.from(params.n);

    assert.throws(() => rsaVerify65537(message, signature, modulus));
  });

  it('should reject non-compliant RSA signature: false signature modulus', async () => {
    let message = SHA2.hash(256, 'hello!');
    const params = generateRsaKeys65537();

    const signature = Bigint2048.from(
      rsaSign(message, { d: params.e, n: 1223n })
    ); // Tamper with signature modulus
    const modulus = Bigint2048.from(params.n);

    assert.throws(() => rsaVerify65537(message, signature, modulus));
  });
});
