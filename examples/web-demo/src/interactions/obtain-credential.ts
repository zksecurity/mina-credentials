import { publicKey } from './mock-wallet';
import { API_URL } from '../config';

export { getProvider, getPublicKey, obtainCredential };

// const store = createStore();
// const providers = store.getProviders();
// const provider = providers.find((p) => p.info.slug === 'pallad')?.provider;

const providers: any[] = [];
window.addEventListener('mina:announceProvider', (event: any) => {
  providers.push(event.detail);
});
window.dispatchEvent(new Event('mina:requestProvider'));
const { provider } = providers.find(
  (provider) => provider.info.slug === 'pallad'
);

type Provider = {
  request<M>(params: { method: M; params?: any; context?: any }): Promise<any>;
};

function getProvider(): Provider {
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
