import { Presentation, PresentationRequest } from '../../../../build/src';
import { getStoredCredentials } from './store-credential';
import { privateKey } from './mock-wallet';
import { API_URL } from '../config';
import { z } from 'zod';

export { loginRequest, submitVote };

async function loginRequest(
  useMockWallet: boolean,
  log: (msg: string) => void = () => {}
) {
  return presentationRequest(
    { GET: 'login-request', POST: 'login' },
    useMockWallet,
    log
  );
}

let PollResults = z.object({
  btc: z.number(),
  eth: z.number(),
  voteCounted: z.boolean(),
  failureReason: z.string(),
});

async function submitVote(
  vote: 'btc' | 'eth',
  useMockWallet: boolean,
  log: (msg: string) => void = () => {}
) {
  log('Submitting vote...');
  // await new Promise((resolve) => setTimeout(resolve, 1000));
  // return {
  //   btc: 95,
  //   eth: 63,
  //   voteCounted: true,
  //   failureReason: 'Duplicate nullifier: Only allowed to vote once',
  // };
  let response = await presentationRequest(
    { GET: 'poll-request', POST: 'poll' },
    useMockWallet,
    log,
    { vote }
  );
  return PollResults.parse(JSON.parse(response));
}

/**
 * General function to handle presentation requests.
 */
async function presentationRequest(
  endpoints: { GET: string; POST: string },
  useMockWallet: boolean,
  log: (msg: string) => void = () => {},
  query?: Record<string, string>
) {
  log('Fetching presentation request...');
  let queryStr = query ? new URLSearchParams(query).toString() : '';
  let response = await fetch(`${API_URL}/${endpoints.GET}?${queryStr}`, {
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
  let response2 = await fetch(`${API_URL}/${endpoints.POST}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: presentation,
  });
  if (!response2.ok) {
    let error = await response2.json();
    throw Error(error.error ?? 'Failed to verify presentation');
  }
  return response2.text();
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
