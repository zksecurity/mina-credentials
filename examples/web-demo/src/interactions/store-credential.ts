import { type StoredCredential, Credential } from '../../../..';
import { getProvider } from './obtain-credential';

export { storeCredential, getStoredCredentials };

async function storeCredential(
  useMockWallet: boolean,
  credential: string
): Promise<void> {
  let storedCredential = await Credential.fromJSON(credential);
  await Credential.validate(storedCredential);

  if (useMockWallet) {
    let credentials = await getStoredCredentialStrings(useMockWallet);
    credentials.push(credential);

    window.localStorage.setItem(
      'storedCredentials',
      JSON.stringify(credentials)
    );
    return;
  }

  let provider = getProvider();

  let { result } = await provider.request<'mina_storePrivateCredential'>({
    method: 'mina_storePrivateCredential',
    params: [JSON.parse(credential)],
  });
  if (!result.success) throw Error('Failed to store credential');
}

async function getStoredCredentialStrings(
  useMockWallet: boolean
): Promise<string[]> {
  if (!useMockWallet)
    throw Error('Cannot get stored credentials from a real wallet');

  let storedCredentials = window.localStorage.getItem('storedCredentials');

  if (storedCredentials === null) return [];

  let parsed = JSON.parse(storedCredentials);
  if (!Array.isArray(parsed)) throw Error('Invalid stored credentials');

  return parsed;
}

async function getStoredCredentials(
  useMockWallet: boolean
): Promise<StoredCredential[]> {
  let storedCredentialStrings = await getStoredCredentialStrings(useMockWallet);

  let storedCredentials = [];
  for (let credential of storedCredentialStrings) {
    storedCredentials.push(await Credential.fromJSON(credential));
  }
  return storedCredentials;
}
