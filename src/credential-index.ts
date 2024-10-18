import {
  createUnsigned,
  Unsigned,
  Proved,
  ProvedFromProgram,
} from './credential.ts';
import { createSigned, Signed } from './credential-signed.ts';
import { type PublicKey } from 'o1js';

export { Credential };

/**
 * A credential is a generic piece of data (the "attributes") along with an owner represented by a public key.
 */
type Credential<Data> = { owner: PublicKey; data: Data };

const Credential = {
  Unsigned,
  Simple: Signed,
  Recursive: Proved,
  RecursiveFromProgram: ProvedFromProgram,

  /**
   * Issue a "simple" signed credential.
   */
  sign: createSigned,

  /**
   * Create a dummy credential with no owner and no signature.
   */
  unsigned: createUnsigned,
};
