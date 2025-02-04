import {
  Bool,
  createEcdsa,
  createForeignCurve,
  Crypto,
  Field,
  Provable,
  Struct,
  UInt8,
} from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { assert, notImplemented, pad } from '../util.ts';
import { DynamicString } from './dynamic-string.ts';
import { DynamicSHA3 } from './dynamic-sha3.ts';
import { assertInRange16 } from './gadgets.ts';
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
  let digits = toBase10BE(value, maxDigits);

  // map the digits to ASCII characters
  let asciiDigits = digits.map(UInt8, (digit) =>
    UInt8.Unsafe.fromField(digit.add(48n).seal())
  );

  // convert to string
  const String = DynamicString({ maxLength: maxDigits });
  return new String(asciiDigits.array, asciiDigits.length);
}

function toBase10BE(value: Field, maxDigits: number): DynamicArray<Field> {
  let digits = Provable.witness(
    DynamicArray(Field, { maxLength: maxDigits }),
    () => {
      let remaining = value.toBigInt();
      let digitsLE: bigint[] = [];
      while (remaining > 0) {
        digitsLE.push(remaining % 10n);
        remaining /= 10n;
      }
      return digitsLE.reverse();
    }
  );
  // all digits are in range
  digits.array.forEach((d) => assertDigit(d));

  // the digits correctly represent the value
  fromBase10BE(digits).assertEquals(value);

  // the most significant digit is not 0, except if the value is 0
  if (maxDigits > 0) {
    digits.array[0]!.equals(0)
      .implies(value.equals(0))
      .assertTrue('most significant digit must not be 0');
  }
  return digits;
}

function fromBase10BE(digits: DynamicArray<Field>): Field {
  // compute powers to multiply digits with
  // 10^3, 10^2, 10^1, 10^0, 0, 0, ..., 0
  //                         ^ length
  let power = Field(1);
  let powers: Field[] = Array(digits.maxLength);
  digits.forEachReverse((_, isPadding, i) => {
    powers[i] = Provable.if(isPadding.not(), power, Field(0));
    if (i > 0) power = Provable.if(isPadding.not(), power.mul(10), power);
  });

  let sum = Field(0);
  digits.forEach((digit, _, i) => {
    sum = sum.add(digit.mul(powers[i]!));
  });
  return sum.seal();
}

function assertDigit(digit: Field) {
  assertInRange16(digit, 9);
}
