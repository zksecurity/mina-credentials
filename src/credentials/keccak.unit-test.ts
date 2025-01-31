import { Bytes, Keccak } from 'o1js';
import { keccak256 } from './keccak-dynamic.ts';
import { assert } from '../util.ts';

let shortMessage = 'hello world';
let longMessage =
  'SHA-3 (Secure Hash Algorithm 3) is the latest[4] member of the Secure Hash Algorithm family of standards, released by NIST on August 5, 2015.[5][6][7] Although part of the same series of standards, SHA-3 is internally different from the MD5-like structure of SHA-1 and SHA-2. ';

assert(
  Keccak.ethereum(Bytes.fromString(shortMessage)).toHex() ===
    keccak256(Bytes.fromString(shortMessage)).toHex(),
  'hashes are not equal (short message)'
);

assert(
  Keccak.ethereum(Bytes.fromString(longMessage)).toHex() ===
    keccak256(Bytes.fromString(longMessage)).toHex(),
  'hashes are not equal (long message)'
);
