import { Bytes, Keccak } from 'o1js';
import { keccak256 } from './keccak-dynamic.ts';
import { assert } from '../util.ts';

let message = Bytes(32).fromString('hello world');

let hash1 = Keccak.ethereum(message);
let hash2 = keccak256(message);

assert(hash1.toHex() === hash2.toHex(), 'hashes are not equal');
