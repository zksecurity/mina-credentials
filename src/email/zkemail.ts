import { readFile } from 'fs/promises';
import { DynamicString } from '../dynamic.ts';
import { Bigint2048, rsaVerify65537 } from '../rsa/rsa.ts';
import { fetchPublicKeyFromDNS, prepareEmailForVerification } from './dkim.ts';
import { assert } from '../util.ts';
import { parseRSASubjectPublicKeyInfo } from './der-parse.ts';
import { fromBase64 } from './base64.ts';
import { bytesToBigintBE } from '../rsa/utils.ts';
import { Bytes } from 'o1js';

type ProvableEmail = {
  /**
   * The email header in canonicalized form, i.e. the form that was signed.
   */
  header: string;

  /**
   * The email body in canonicalized form, i.e. the form that was signed.
   */
  body: string;

  /**
   * RSA public key that signed the email.
   */
  publicKey: Bigint2048;

  /**
   * The RSA signature of the email.
   */
  signature: Bigint2048;
};

let email = await readFile(
  `${import.meta.dirname}/test-emails/email-good.eml`,
  'utf-8'
);
let { body, header, publicKey, signature } = await prepareProvableEmail(email);

// provable types with max lengths
let Body = DynamicString({ maxLength: 700 });
let Header = DynamicString({ maxLength: 500 });

// compute and compare the body hash
let bodyHash = Body.from(body).hashToBytes('sha2-256');
let bodyHashBase64 = bodyHash.base64Encode();

// TODO: show that body hash is contained at the correct position from header,
// using a secure string matching circuit
// (might be helpful to use the dkim header as hint since it is fairly strictly formatted,
// and known to come last in the header, and then reassemble with the other headers)

// hash the header
let headerHash = Header.from(header).hashToBytes('sha2-256');

// verify the signature
rsaVerify65537(headerHash, signature, publicKey);

async function prepareProvableEmail(email: string): Promise<ProvableEmail> {
  let { canonicalBody, canonicalHeader, dkimHeader } =
    prepareEmailForVerification(email);
  assert(dkimHeader.hashAlgo === 'sha256', 'must use sha256 hash');
  assert(dkimHeader.signAlgo === 'rsa', 'must use rsa signature');

  let { publicKeyBytesDer, modulusLength } = await fetchPublicKeyFromDNS(
    dkimHeader
  );
  assert(modulusLength === 2048, 'modulus length must be 2048');

  // parse DER-encoded `SubjectPublicKeyInfo`
  let { n, e } = parseRSASubjectPublicKeyInfo(publicKeyBytesDer);

  assert(e === 65537n, 'public exponent must be 65537');
  let publicKey = Bigint2048.from(n);

  // signature encoding:
  // https://datatracker.ietf.org/doc/html/rfc3447#section-4.1
  let s = bytesToBigintBE(fromBase64(dkimHeader.signature));
  let signature = Bigint2048.from(s);

  return { header: canonicalHeader, body: canonicalBody, publicKey, signature };
}
