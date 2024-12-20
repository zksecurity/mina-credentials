import { publicKey } from './mock-wallet';
import { API_URL } from '../config';
import { createStore } from '@mina-js/connect';

export { getProvider, getPublicKey, obtainCredential };

const store = createStore();
const providers = store.getProviders();
const provider = providers.find((p) => p.info.slug === 'pallad')?.provider;

function getProvider() {
  if (!provider) throw Error('Provider not found');
  return provider;
}

async function getPublicKey(useMockWallet: boolean): Promise<string> {
  if (useMockWallet) return publicKey.toBase58();

  let { result: accounts } =
    await getProvider().request<'mina_requestAccounts'>({
      method: 'mina_requestAccounts',
    });

  if (accounts.length === 0) throw Error('No accounts found');
  return accounts[0];
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
