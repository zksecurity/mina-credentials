import { PublicKey } from 'o1js';
import { Credential } from '../../../..';
import { privateKey, publicKey } from './mock-wallet';
import { dataFromInput, DataInput } from '../common/schema';
import { API_URL } from '../config';

export { getPublicKey, issueCredential };

async function getPublicKey(useMockWallet: boolean): Promise<string> {
  if (useMockWallet) return publicKey.toBase58();

  return 'NOT_IMPLEMENTED';
}

async function issueCredential(
  useMockWallet: boolean,
  ownerPublicKey: string,
  dataInput: DataInput
): Promise<string> {
  let owner = PublicKey.fromBase58(ownerPublicKey);
  let data = dataFromInput(dataInput);

  let response = await fetch(`${API_URL}/issue-credential`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: Credential.dataToJSON({ owner, data }),
  });

  if (!response.ok) {
    let error = await response.json();
    throw Error(error.error ?? 'Failed to issue credential');
  }
  return await response.text();
}
