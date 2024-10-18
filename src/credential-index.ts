import { None, Proved, ProvedFromProgram } from './credentials.ts';
import { SignedCredential } from './credential-issuance.ts';
import { type PublicKey } from 'o1js';

export { Credential };

/**
 * A credential is a generic piece of data (the "attributes") along with an owner represented by a public key.
 */
type Credential<Data> = { owner: PublicKey; data: Data };

const Credential = {
  none: None,
  proof: Proved,
  proofFromProgram: ProvedFromProgram,
  signature: SignedCredential,
};
