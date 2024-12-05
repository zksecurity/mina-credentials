import { readFile } from 'fs/promises';
import { DynamicString } from '../dynamic.ts';
import { Bigint2048 } from '../rsa/rsa.ts';
import { fetchPublicKeyFromDNS, prepareEmailForVerification } from './dkim.ts';
import { assert } from '../util.ts';
import { parseRSASubjectPublicKeyInfo } from './der-parse.ts';

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
let provableEmail = await prepareProvableEmail(email);
console.log(provableEmail);

async function prepareProvableEmail(email: string): Promise<ProvableEmail> {
  let { canonicalBody, canonicalHeader, dkimHeader } =
    prepareEmailForVerification(email);

  let { publicKeyBytesDer, modulusLength } = await fetchPublicKeyFromDNS(
    dkimHeader
  );
  assert(modulusLength === 2048, 'Invalid modulus length');

  // parse DER-encoded `SubjectPublicKeyInfo`
  let { n, e } = parseRSASubjectPublicKeyInfo(publicKeyBytesDer);

  // public exponent MUST be 65537
  assert(e === 65537n, 'public exponent is 65537');
  let publicKey = Bigint2048.from(n);

  return {
    header: canonicalHeader,
    body: canonicalBody,
    publicKey,
    signature: Bigint2048.from(0n), // TODO
  };
}
