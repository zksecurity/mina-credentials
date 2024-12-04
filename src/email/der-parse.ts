/**
 * Minimal version of a DER parsing library (in parser-combinator style),
 * sufficient to parse a RSA public key in SubjectPublicKeyInfo format.
 */
import type { Tuple } from '../types.ts';
import { arrayEqual, assert, defined } from '../util.ts';

export { parse, Sequence, ObjectIdentifier, Null, BitString, Integer };
export { parseRSASubjectPublicKeyInfo };

/**
 * An Offset is a number that can be increased
 */
class Offset {
  i: number;
  constructor(i = 0) {
    this.i = i;
  }
  incr() {
    return this.i++;
  }
  incrBy(n: number) {
    return (this.i += n);
  }
  copy() {
    return new Offset(this.i);
  }
}

/**
 * A Parser is a function that takes a byte array and an offset,
 * and either returns the parsed value and increments the offset,
 * or throws an error.
 */
type Parser<T = any> = (bytes: Uint8Array, offset: Offset) => T;

/**
 * Parse a byte array using a parser.
 *
 * Asserts that the parser consumes all bytes.
 */
function parse<T>(parser: Parser<T>, bytes: Uint8Array) {
  let offset = new Offset();
  let result = parser(bytes, offset);
  assert(bytes.length === offset.i, 'all bytes consumed');
  return result;
}

// DER constants

const PRIMITIVE = 0b0 << 5;
const CONSTRUCTED = 0b1 << 5;
const UNIVERSAL = 0 << 6;

const TAG_INTEGER = 0x02;
const OCTET_INTEGER = TAG_INTEGER | PRIMITIVE | UNIVERSAL;

const TAG_BIT_STRING = 0x03;
const OCTET_BIT_STRING = TAG_BIT_STRING | PRIMITIVE | UNIVERSAL;

const TAG_NULL = 0x05;
const OCTET_NULL = TAG_NULL | PRIMITIVE | UNIVERSAL;

const TAG_OBJECT_IDENTIFIER = 0x06;
const OCTET_OBJECT_IDENTIFIER = TAG_OBJECT_IDENTIFIER | PRIMITIVE | UNIVERSAL;

const TAG_SEQUENCE = 0x10;
const OCTET_SEQUENCE = TAG_SEQUENCE | CONSTRUCTED | UNIVERSAL;

const IS_LENGTH_LONG = 0b1 << 7;

// DER helper parsers

function Byte(bytes: Uint8Array, offset: Offset) {
  return defined(bytes[offset.incr()]);
}

function Length(bytes: Uint8Array, offset: Offset) {
  let byte = Byte(bytes, offset);
  if (!(byte & IS_LENGTH_LONG)) {
    // short form
    return byte & 0b0111_1111;
  }
  // long form
  let nBytes = byte & 0b0111_1111;
  let length = 0;
  for (let i = 1; i <= nBytes; i++) {
    let byte = Byte(bytes, offset);
    length = (length << 8) + byte;
  }
  return length;
}

function TagLength(
  label: string,
  expectedTag: number,
  bytes: Uint8Array,
  offset: Offset
) {
  let byte = Byte(bytes, offset);
  assert(
    byte === expectedTag,
    () =>
      `${label} tag: expected ${expectedTag.toString(16)}, got ${byte.toString(
        16
      )}`
  );
  return Length(bytes, offset);
}

// basic DER types and combinators

function Sequence<T extends Tuple<Parser>>(
  parsers: T
): Parser<{ [K in keyof T]: ReturnType<T[K]> }> {
  return function parseSequence(bytes: Uint8Array, offset: Offset) {
    let length = TagLength('Sequence', OCTET_SEQUENCE, bytes, offset);
    let targetOffset = offset.i + length;
    let results = parsers.map((parser) => parser(bytes, offset));
    assert(offset.i === targetOffset, 'sequence length matches');
    return results as { [K in keyof T]: ReturnType<T[K]> };
  };
}

function firstOidOctet(bytes: Uint8Array, offset: Offset) {
  let byte = Byte(bytes, offset);
  let value2 = byte % 40;
  let value1 = (byte - value2) / 40;
  return [value1, value2];
}
function nextOidValue(bytes: Uint8Array, offset: Offset) {
  // a sort of LEB128 encoding
  let value = 0;
  let byte = Byte(bytes, offset);
  while (byte & 0b1000_0000) {
    value = (value << 7) + (byte & 0b0111_1111);
    byte = Byte(bytes, offset);
  }
  value = (value << 7) + (byte & 0b0111_1111);
  return value;
}

function ObjectIdentifier(bytes: Uint8Array, offset: Offset) {
  let length = TagLength(
    'ObjectIdentifier',
    OCTET_OBJECT_IDENTIFIER,
    bytes,
    offset
  );
  let targetOffset = offset.i + length;

  if (length === 0) return [];
  let values = firstOidOctet(bytes, offset);
  while (offset.i < targetOffset) {
    values.push(nextOidValue(bytes, offset));
  }
  assert(offset.i === targetOffset, 'object identifier length matches');
  return values;
}

function Null(bytes: Uint8Array, offset: Offset) {
  let length = TagLength('Null', OCTET_NULL, bytes, offset);
  assert(length === 0, 'NULL length');
  return null;
}

function BitString(bytes: Uint8Array, offset: Offset) {
  let length = TagLength('BitString', OCTET_BIT_STRING, bytes, offset);
  let unusedBits = Byte(bytes, offset);
  length--; // unused bits byte
  assert(unusedBits < 8, 'unused bits');
  assert(unusedBits < 8 * length, 'unused bits');
  let content = bytes.slice(offset.i, offset.incrBy(length));
  assert(content.length === length, 'bit string content long enough');
  return { content, unusedBits };
}

function Integer(bytes: Uint8Array, offset: Offset) {
  let length = TagLength('Integer', OCTET_INTEGER, bytes, offset);

  // there has to be at least one byte
  assert(length > 0, 'integer length');
  let msb = Byte(bytes, offset);
  let isNegative = !!(msb >> 7);
  let integer = BigInt(msb & 0b0111_1111);

  let remainder = bytes.subarray(offset.i, offset.incrBy(length - 1));
  for (let byte of remainder) {
    integer = (integer << 8n) + BigInt(byte);
  }
  return isNegative ? -integer : integer;
}

// AlgorithmIdentifier  ::=  SEQUENCE  {
//   algorithm               OBJECT IDENTIFIER,
//   parameters              ANY DEFINED BY algorithm OPTIONAL  }

// pkcs-1  OBJECT IDENTIFIER  ::=  { iso(1) member-body(2)
//   us(840) rsadsi(113549) pkcs(1) 1 }

// rsaEncryption OBJECT IDENTIFIER ::=  { pkcs-1 1 }
// sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 11 }

const OID_PKCS1 = [1, 2, 840, 113549, 1, 1];
const OID_RSA = [...OID_PKCS1, 1];
const OID_RSA_SHA256 = [...OID_PKCS1, 11];

function RsaAlgorithmIdentifier(bytes: Uint8Array, offset: Offset) {
  let [oid] = Sequence([ObjectIdentifier, Null])(bytes, offset);
  assert(
    arrayEqual(oid, OID_RSA) || arrayEqual(oid, OID_RSA_SHA256),
    'algorithm is sha256WithRSAEncryption or rsaEncryption'
  );
  return oid;
}

// SubjectPublicKeyInfo  ::=  SEQUENCE  {
//   algorithm            AlgorithmIdentifier,
//   subjectPublicKey     BIT STRING  }

const SubjectPublicKeyInfo = Sequence([RsaAlgorithmIdentifier, BitString]);

// the bit string's content is a DER-encoded RSAPublicKey:

// RSAPublicKey ::= SEQUENCE {
//   modulus            INTEGER,    -- n
//   publicExponent     INTEGER  }  -- e

const RSAPublicKey = Sequence([Integer, Integer]);

/**
 * Parse a RSA public key in SubjectPublicKeyInfo format,
 * returning the modulus `n` as a bigint.
 */
function parseRSASubjectPublicKeyInfo(bytes: Uint8Array) {
  let [, subjectPublicKey] = parse(SubjectPublicKeyInfo, bytes);

  let { content: rsaPublicKeyBytes, unusedBits } = subjectPublicKey;
  assert(unusedBits === 0, 'no unused bits for RSAPublicKey');

  let [n, e] = parse(RSAPublicKey, rsaPublicKeyBytes);
  return { n, e };
}
