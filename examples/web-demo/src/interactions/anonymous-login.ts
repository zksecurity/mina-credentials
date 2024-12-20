import { Presentation, PresentationRequest } from '../../../../build/src';
import { getStoredCredentials } from './store-credential';
import { privateKey } from './mock-wallet';
import { API_URL } from '../config';

export { loginRequest };

async function loginRequest(
  useMockWallet: boolean,
  log: (msg: string) => void = () => {}
) {
  log('Sending login request...');
  let response = await fetch(`${API_URL}/anonymous-login-request`, {
    method: 'GET',
  });
  if (!response.ok) {
    let error = await response.json();
    throw Error(error.error ?? 'Failed to request presentation');
  }
  let requestJson = await response.text();

  if (!useMockWallet) throw Error('Not implemented');

  log('Awaiting proof from wallet...');
  let presentation = await createMockPresentation(requestJson);

  log('Sending proof for verification...');
  let response2 = await fetch(`${API_URL}/anonymous-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: presentation,
  });
  if (!response2.ok) {
    let error = await response2.json();
    throw Error(error.error ?? 'Failed to verify presentation');
  }
}

async function createMockPresentation(requestJson: string) {
  let credentials = await getStoredCredentials(true);

  let request = PresentationRequest.fromJSON('https', requestJson);
  console.time('compile');
  await Presentation.compile(request);
  console.timeEnd('compile');

  console.time('create');
  let presentation = await Presentation.create(privateKey, {
    request,
    credentials,
    context: { verifierIdentity: window.location.hostname },
  });
  console.timeEnd('create');

  return Presentation.toJSON(presentation);
}
