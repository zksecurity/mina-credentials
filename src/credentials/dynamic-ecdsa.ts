import {
  Bool,
  createEcdsa,
  createForeignCurve,
  Crypto,
  Field,
  Gadgets,
  Provable,
  UInt8,
} from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { fill, notImplemented } from '../util.ts';
import { DynamicString } from './dynamic-string.ts';
import { DynamicSHA3 } from './dynamic-sha3.ts';
import { assertInRange16, assertLessThan16 } from './gadgets.ts';
import { log } from './dynamic-hash.ts';

export { EcdsaEthereum, toDigits };

class Secp256k1 extends createForeignCurve(Crypto.CurveParams.Secp256k1) {}
class EcdsaSignature extends createEcdsa(Secp256k1) {}

const EcdsaEthereum = {
  Signature: EcdsaSignature,
  PublicKey: Secp256k1,

  verify: verifyEthereumSignature,

  Recursive: {
    verify: notImplemented,
  },
};

// Ethereum-specific prefix for signing
const messagePrefix = '\x19Ethereum Signed Message:\n';

function verifyEthereumSignature(
  message: DynamicArray<UInt8>,
  signature: EcdsaSignature,
  publicKey: Secp256k1
) {
  // encode message by prepending Ethereum prefix and encoded message length
  let encodedMessage = DynamicString.from(messagePrefix)
    // note: 5 base10 digits are enough because DynamicString only supports length < 2^16
    .concat(toDigits(message.length, 5))
    .concat(message);

  log('encodedMessage', encodedMessage);

  // hash message using dynamic Keccak256
  let hash = DynamicSHA3.keccak256(encodedMessage);

  // verify signature on hash
  let ok = signature.verifySignedHash(hash, publicKey);
  ok.assertTrue('signature is invalid');
}

function toDigits(value: Field, maxDigits: number): DynamicString {
  let digits = toBase10(value, maxDigits);
  let length = Provable.witness(Field, () =>
    Number(value) === 0 ? 0 : value.toString().length
  );
  assertInRange16(length, maxDigits); // length <= maxDigits

  // prove that length is correct, by showing that all digits beyond the length are 0 and the last one before is not
  let afterLast = length.equals(0);
  digits.forEach((digit, i) => {
    let isLast = length.equals(i + 1);
    let isZero = digit.equals(0);

    isLast.and(isZero).assertFalse('last digit must not be 0');
    afterLast.implies(isZero).assertTrue('digits beyond length must be 0');

    afterLast = afterLast.or(isLast);
  });

  // we map the digits to ASCII characters
  // and reverse them, because we computed them in little-endian order
  const String = DynamicString({ maxLength: maxDigits });
  let reverseAsciiDigits = digits.map(digitToAscii);
  return new String(reverseAsciiDigits, length).reverse();
}

function digitToAscii(digit: Field) {
  return UInt8.Unsafe.fromField(digit.add(48n).seal());
}

function toBase10(value: Field, maxDigits: number): Field[] {
  let digits = Provable.witnessFields(maxDigits, () => {
    let remaining = value.toBigInt();
    let result = Array<bigint>(maxDigits);
    for (let i = 0; i < maxDigits; i++) {
      result[i] = remaining % 10n;
      remaining /= 10n;
    }
    return result;
  });
  digits.forEach(assertDigit);
  fromBase10(digits).assertEquals(value);
  return digits;
}

function fromBase10(digits: Field[]): Field {
  let sum = Field(0);
  digits.forEach((digit, i) => {
    sum = sum.add(digit.mul(10n ** BigInt(i)));
  });
  return sum.seal();
}

function assertDigit(digit: Field) {
  assertInRange16(digit, 9);
}
