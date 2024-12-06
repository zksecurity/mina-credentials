import { DynamicString, StaticArray } from '../dynamic.ts';
import { Bigint2048, rsaVerify65537 } from '../rsa/rsa.ts';
import { fetchPublicKeyFromDNS, prepareEmailForVerification } from './dkim.ts';
import { assert } from '../util.ts';
import { parseRSASubjectPublicKeyInfo } from './der-parse.ts';
import { fromBase64 } from './base64.ts';
import { bytesToBigintBE } from '../rsa/utils.ts';
import { Struct, UInt8 } from 'o1js';

export { ProvableEmail, verifyEmail, prepareProvableEmail };

type ProvableEmail = {
  /**
   * The email header in canonicalized form, i.e. the form that was signed.
   */
  header: string | DynamicString;

  /**
   * The email body in canonicalized form, i.e. the form that was signed.
   */
  body: string | DynamicString;

  /**
   * RSA public key that signed the email.
   */
  publicKey: Bigint2048;

  /**
   * The RSA signature of the email.
   */
  signature: Bigint2048;
};

/**
 * Simple provable method to verify an email for demonstration purposes.
 *
 * Uses more than 150k constraints so needs breaking up into several proofs to actually use.
 */
function verifyEmail(email: ProvableEmail) {
  // provable types with max lengths
  let body = DynamicString.from(email.body);
  let header = DynamicString.from(email.header);

  // compute and compare the body hash
  // TODO: this needs a recursive proof
  let bodyHash = body.hashToBytes('sha2-256');
  let bodyHashBase64 = bodyHash.base64Encode();

  // TODO: show that body hash is contained at the correct position from header,
  // using a secure string matching circuit
  // (might be helpful to use the dkim header as hint since it is fairly strictly formatted,
  // and known to come last in the header, and then reassemble with the other headers)

  // TODO: this is just a sanity check and not secure at all
  header.assertContains(
    StaticArray.from(UInt8, bodyHashBase64.bytes),
    'verifyEmail: body hash mismatch'
  );

  // hash the header
  // TODO: this needs a recursive proof
  let headerHash = header.hashToBytes('sha2-256');

  // verify the signature
  rsaVerify65537(headerHash, email.signature, email.publicKey);
}

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

function ProvableEmail({
  maxHeaderLength,
  maxBodyLength,
}: {
  maxHeaderLength: number;
  maxBodyLength: number;
}) {
  const Header = DynamicString({ maxLength: maxHeaderLength });
  const Body = DynamicString({ maxLength: maxBodyLength });

  return class extends Struct({
    header: Header,
    body: Body,
    publicKey: Bigint2048,
    signature: Bigint2048,
  }) {
    static Header = Header;
    static Body = Body;
  };
}
