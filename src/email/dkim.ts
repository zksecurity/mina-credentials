import { readFile } from 'fs/promises';
import path from 'path';
import { assert, assertDefined } from '../util.ts';
import parseDkimHeaders from './lib/mailauth/parse-dkim-headers.ts';
import { TupleN } from 'o1js';

let dec = new TextDecoder();
let enc = new TextEncoder();

let email = await readFile(
  path.resolve(import.meta.dirname, './email-good.eml'),
  'utf-8'
);

console.log(email);

let emailBytes = enc.encode(email);
let { headerBytes, bodyBytes } = splitEmail(emailBytes);

let header = dec.decode(headerBytes);
let body = dec.decode(bodyBytes);

console.log({ header, body });

let headers = parseHeaders(header);
console.log(headers);

// TODO: is it correct to only look for the first DKIM header?
let dkimHeaderRaw = headers.find((h) => h.key === 'dkim-signature');
assertDefined(dkimHeaderRaw, 'No DKIM signature found');

let dkimHeaderParsed = parseDkimHeaders(dkimHeaderRaw.line).parsed;
assertDefined(dkimHeaderParsed, 'Failed to parse DKIM header');

let dkimHeader = validateDkimHeader(dkimHeaderParsed);
console.log(dkimHeader);

/**
 * Find end of the header and split the email into header and body
 */
function splitEmail(emailBytes: Uint8Array) {
  let n = emailBytes.length;
  let headerLength: undefined | number;

  const LF = 0x0a; // \n
  const CR = 0x0d; // \r

  // header ends with either \n\n or \n\r\n
  for (let i = 0; i < n; i++) {
    let b0 = emailBytes[i];
    if (b0 === LF && i > 0) {
      let b1 = emailBytes[i - 1];
      let b2 = emailBytes[i - 2];
      if (b1 === LF || (b1 === CR && b2 === LF)) {
        headerLength = i + 1;
        break;
      }
    }
  }
  assert(headerLength !== undefined, 'No end of header found');

  let headerBytes = emailBytes.subarray(0, headerLength);
  let bodyBytes = emailBytes.subarray(headerLength);
  return { headerBytes, bodyBytes };
}

/**
 * Parse email headers into individual lines with keys
 *
 * This was copied and modified from zk-email-verify, which copied and modified from mailauth:
 * https://github.com/postalsys/mailauth
 */
function parseHeaders(headerString: string) {
  let rows: string[][] = headerString
    .replace(/[\r\n]+$/, '')
    .split(/\r?\n/)
    .map((row) => [row]);

  for (let i = rows.length - 1; i > 0; i--) {
    if (/^\s/.test(rows[i]![0]!)) {
      rows[i - 1] = rows[i - 1]!.concat(rows[i]!);
      rows.splice(i, 1);
    }
  }

  return rows.map((row) => {
    let line = row.join('\r\n');
    let key: RegExpMatchArray | string | null = line.match(/^[^:]+/);
    if (key) {
      key = key[0].trim().toLowerCase();
    }

    // return { key, line: enc.encode(line) };
    return { key, line };
  });
}

/**
 * Validate and extract DKIM header fields after initial parsing
 */
function validateDkimHeader(dkimHeader: ParsedDkimHeader) {
  // validate algorithms
  let algorithm = dkimHeader.a?.value;
  assertString(algorithm, 'Invalid algorithm');
  let [signAlgo, hashAlgo] = TupleN.fromArray(2, algorithm.split('-'));
  signAlgo = signAlgo.toLowerCase().trim();
  hashAlgo = hashAlgo.toLowerCase().trim();
  assertContains(['rsa', 'ed25519'], signAlgo, 'Invalid sign algorithm');
  assertContains(['sha256', 'sha1'], hashAlgo, 'Invalid hash algorithm');

  // validate canonicalization
  let canonicalization = dkimHeader.c?.value;
  assertString(canonicalization, 'Invalid canonicalization');
  let [headerCanon, bodyCanon] = canonicalization.split('/');
  headerCanon = headerCanon?.toLowerCase().trim();
  // if body canonicalization is not set, then defaults to 'simple'
  bodyCanon = (bodyCanon || 'simple').toLowerCase().trim();
  assertContains(['simple', 'relaxed'], headerCanon, 'Invalid header canon');
  assertContains(['simple', 'relaxed'], bodyCanon, 'Invalid body canon');

  // validate max body length and body hash
  let maxBodyLength = dkimHeader.l?.value;
  assert(
    maxBodyLength === undefined ||
      (typeof maxBodyLength === 'number' && !isNaN(maxBodyLength)),
    'Invalid max body length'
  );
  let bodyHashSpec = { bodyCanon, hashAlgo, maxBodyLength };

  let bodyHash = dkimHeader.bh?.value;
  assertString(bodyHash, 'Invalid body hash');

  // validate signing domain and selector
  let signingDomain = dkimHeader.d?.value;
  let selector = dkimHeader.s?.value;
  assertNonemptyString(signingDomain, 'Invalid signing domain');
  assertNonemptyString(selector, 'Invalid selector');

  return {
    signAlgo,
    hashAlgo,
    headerCanon,
    bodyCanon,
    signingDomain,
    selector,
    bodyHashSpec,
    bodyHash,
  };
}

type ParsedDkimHeader = {
  a?: { value: unknown };
  c?: { value: unknown };
  d?: { value: unknown };
  s?: { value: unknown };
  bh?: { value: unknown };
  l?: { value: unknown };
  // b?: { value: unknown };
  // h?: { value: unknown };
  // v?: { value: unknown };
  // t?: { value: unknown };
};

function assertString(
  value: unknown,
  message: string
): asserts value is string {
  assert(typeof value === 'string', message);
}
function assertNonemptyString(
  value: unknown,
  message: string
): asserts value is string {
  assert(typeof value === 'string' && value !== '', message);
}

function assertContains<const T extends any[]>(
  arr: T,
  value: unknown,
  message: string
): asserts value is T[number] {
  assert(arr.includes(value), message);
}
