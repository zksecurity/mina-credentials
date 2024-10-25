import { Field, PrivateKey, Proof } from 'o1js';
import {
  Spec,
  type Input,
  type Claims,
  type PublicInputs,
} from './program-spec.ts';
import { createProgram, type Program } from './program.ts';
import {
  signCredentials,
  type CredentialSpec,
  type StoredCredential,
} from './credential.ts';
import { assert } from './util.ts';
import { serializePresentationRequest } from './serialize-spec.ts';
import { deserializePresentationRequest } from './deserialize-spec.ts';

export { PresentationRequest, Presentation };

type PresentationRequestType = 'no-context';

type PresentationRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>,
  InputContext = any,
  WalletContext = any
> = {
  type: PresentationRequestType;
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext?: InputContext;

  deriveContext(walletContext?: WalletContext): Field;
};

const PresentationRequest = {
  noContext<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>
  ) {
    return {
      type: 'no-context',
      spec,
      claims,
      deriveContext: () => Field(0),
    } satisfies PresentationRequest;
  },

  toJSON(request: PresentationRequest) {
    return JSON.stringify(serializePresentationRequest(request));
  },
  fromJSON<P extends PresentationRequest = PresentationRequest>(
    json: string
  ): P {
    return deserializePresentationRequest(JSON.parse(json)) as P;
  },
};

type Presentation<Output, Inputs extends Record<string, Input>> = {
  version: 'v0';
  claims: Claims<Inputs>;
  outputClaim: Output;
  proof: Proof<PublicInputs<Inputs>, Output>;
};

type Output<R> = R extends PresentationRequest<infer O> ? O : never;
type Inputs<R> = R extends PresentationRequest<any, infer I> ? I : never;

const Presentation = {
  async compile<R extends PresentationRequest>(
    request: R
  ): Promise<R & { program: Program<Output<R>, Inputs<R>> }> {
    let program: Program<Output<R>, Inputs<R>> = (request as any).program ??
    createProgram(request.spec);
    await program.compile();
    return { ...request, program };
  },

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
  let { program } = await Presentation.compile(request);

  let credentialsNeeded = Object.entries(request.spec.inputs).filter(
    (c): c is [string, CredentialSpec] => c[1].type === 'credential'
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
