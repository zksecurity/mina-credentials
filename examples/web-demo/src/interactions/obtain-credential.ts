import { PublicKey, UInt64 } from 'o1js';
import { Credential } from '../../../../build/src';
import { publicKey } from './mock-wallet';
import { API_URL } from '../config';

export { getPublicKey, obtainCredential };

async function getPublicKey(useMockWallet: boolean): Promise<string> {
  if (useMockWallet) return publicKey.toBase58();

  return 'NOT_IMPLEMENTED';
}

type UserInput = {
  name: string;
  birthDate: number;
  nationality: string;
};

async function obtainCredential(
  owner: string,
  data: UserInput
): Promise<string> {
  let response = await fetch(`${API_URL}/issue-credential`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ owner, data }),
  });

  if (!response.ok) {
    let error = await response.json();
    throw Error(error.error ?? 'Failed to issue credential');
  }
  return await response.text();
}
