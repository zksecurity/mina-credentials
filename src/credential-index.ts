import { createUnsigned, Unsigned } from './credential.ts';
import { createSigned, Signed } from './credential-signed.ts';
import { type PublicKey } from 'o1js';
import { Recursive } from './credential-recursive.ts';

export { Credential };

/**
 * A credential is a generic piece of data (the "attributes") along with an owner represented by a public key.
 */
type Credential<Data> = { owner: PublicKey; data: Data };

const Credential = {
  Unsigned,
  Simple: Signed,
  Recursive,

  /**
   * Issue a "simple" signed credential.
   */
  sign: createSigned,

  /**
   * Create a dummy credential with no owner and no signature.
   */
  unsigned: createUnsigned,
};
