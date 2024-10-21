import { Field, PrivateKey, Proof, PublicKey } from 'o1js';
import {
  Spec,
  type Input,
  type Claims,
  type PublicInputs,
} from './program-spec.ts';
import { createProgram } from './program.ts';
import {
  signCredentials,
  type CredentialType,
  type StoredCredential,
} from './credential.ts';
import { assert } from './util.ts';

export { PresentationRequest, Presentation };

type PresentationRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>,
  InputContext = any,
  WalletContext = any
> = {
  programSpec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext?: InputContext;

  deriveContext(walletContext?: WalletContext): Field;
};

const PresentationRequest = {
  noContext<Output, Inputs extends Record<string, Input>>(
    programSpec: Spec<Output, Inputs>,
    claims: Claims<Inputs>
  ) {
    return {
      programSpec,
      claims,
      deriveContext: () => Field(0),
    } satisfies PresentationRequest;
  },
};

type Presentation<Output, Inputs extends Record<string, Input>> = {
  version: 'v0';
  claims: Claims<Inputs>;
  outputClaim: Output;
  proof: Proof<PublicInputs<Inputs>, Output>;
};

const Presentation = {
  create: createPresentation,
};

async function createPresentation<
  Output,
  Inputs extends Record<string, Input>,
  InputContext,
  WalletContext
>(
  ownerKey: PrivateKey,
  {
    request,
    walletContext,
    credentials,
  }: {
    request: PresentationRequest<Output, Inputs, InputContext, WalletContext>;
    walletContext?: WalletContext;
    credentials: (StoredCredential & { key?: string })[];
  }
): Promise<Presentation<Output, Inputs>> {
  let context = request.deriveContext(walletContext);
  let program = createProgram(request.programSpec);
  await program.compile();

  let credentialsNeeded = Object.entries(request.programSpec.inputs).filter(
    (c): c is [string, CredentialType] => c[1].type === 'credential'
  );
  let credentialsUsed = pickCredentials(
    credentialsNeeded.map(([key]) => key),
    credentials
  );
  let ownerSignature = signCredentials(
    ownerKey,
    context,
    ...credentialsNeeded.map(([key, input]) => ({
      ...credentialsUsed[key]!,
      credentialType: input,
    }))
  );

  let proof = await program.run({
    context,
    claims: request.claims,
    ownerSignature,
    credentials: credentialsUsed as any,
  });

  return {
    version: 'v0',
    claims: request.claims,
    outputClaim: proof.publicOutput,
    proof,
  };
}

function pickCredentials(
  credentialsNeeded: string[],
  [...credentials]: (StoredCredential & { key?: string })[]
): Record<string, StoredCredential> {
  let credentialsUsed: Record<string, StoredCredential> = {};
  let credentialsStillNeeded: string[] = [];

  for (let key of credentialsNeeded) {
    let i = credentials.findIndex((c) => c.key === key);
    if (i === -1) {
      credentialsStillNeeded.push(key);
      continue;
    } else {
      credentialsUsed[key] = credentials[i]!;
      credentials.splice(i, 1);
    }
  }
  let i = 0;
  for (let credential of credentials) {
    if (credentialsStillNeeded.length === 0) break;
    credentialsUsed[credentialsStillNeeded.shift()!] = credential;
    i++;
  }
  assert(
    credentialsStillNeeded.length === 0,
    `Missing credentials: ${credentialsStillNeeded.join(', ')}`
  );
  return credentialsUsed;
}
