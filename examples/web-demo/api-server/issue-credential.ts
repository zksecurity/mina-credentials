import { CredentialData, schema } from './schema.ts';
import { Bytes, PublicKey } from 'o1js';
import { Credential } from '../../../src/index.ts';
import { getPrivateKey } from './keys.ts';

export { issueCredential };

const Bytes16 = Bytes(16);

function issueCredential(userString: string) {
  let userData = CredentialData.parse(JSON.parse(userString));
  let {
    owner,
    data: { name, nationality, birthDate },
  } = userData;

  // random 16 bytes ID
  let id = Bytes16.random();

  // expires in 1 year
  let expiresAt = Date.now() + 365 * 24 * 3600 * 1000;

  let credential = {
    owner: PublicKey.fromBase58(owner),
    data: schema.from({ name, nationality, birthDate, id, expiresAt }),
  };

  let signed = Credential.sign(getPrivateKey(), credential);
  return Credential.toJSON(signed);
}
