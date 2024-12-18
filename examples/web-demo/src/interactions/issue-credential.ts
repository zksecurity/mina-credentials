import { Bytes, PrivateKey, PublicKey } from 'o1js';
import { Credential, Schema } from '../../../..';

export { getPublicKey, issueCredential, type Data, privateKey };

let { privateKey, publicKey } = PrivateKey.randomKeypair();

async function getPublicKey(useMockWallet: boolean): Promise<string> {
  if (useMockWallet) {
    return publicKey.toBase58();
  } else {
    return 'NOT_IMPLEMENTED';
  }
}

type DataInput = {
  name: string;
  birthDate: number;
  nationality: string;
  id: string;
  expiresAt: number;
};

const Bytes16 = Bytes(16);

const schema = Schema({
  /**
   * Nationality of the owner.
   */
  nationality: Schema.String,

  /**
   * Full name of the owner.
   */
  name: Schema.String,

  /**
   * Date of birth of the owner.
   */
  birthDate: Schema.Number,

  /**
   * Owner ID (16 bytes).
   */
  id: Bytes16,

  /**
   * Timestamp when the credential expires.
   */
  expiresAt: Schema.Number,
});

type Data = ReturnType<typeof schema.from>;

async function issueCredential(
  useMockWallet: boolean,
  ownerPublicKey: string,
  dataInput: DataInput
): Promise<string> {
  if (!useMockWallet) return 'NOT_IMPLEMENTED';

  let owner = PublicKey.fromBase58(ownerPublicKey);
  let id = Bytes16.fromHex(dataInput.id);
  let data = schema.from({ ...dataInput, id });

  let credential = Credential.sign(privateKey, { owner, data });
  return Credential.toJSON(credential);
}
