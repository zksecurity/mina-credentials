import { None, Proved, ProvedFromProgram } from './credential.ts';
import {
  createSignedCredential,
  SignedCredential,
} from './credential-signed.ts';
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

  /**
   * Issue a signed credential.
   */
  sign: createSignedCredential,
};
