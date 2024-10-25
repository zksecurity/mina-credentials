import { Field, Poseidon, PrivateKey, Proof, PublicKey, Struct } from 'o1js';
import {
  Spec,
  type Input,
  type Claims,
  type PublicInputs,
} from './program-spec.ts';
import { createProgram, type Program } from './program.ts';
import {
  signCredentials,
  type CredentialType,
  type StoredCredential,
} from './credential.ts';
import { assert } from './util.ts';
import { generateContext, computeContext } from './context.ts';
import { NestedProvable } from './nested.ts';
import { serializePresentationRequest } from './serialize-spec.ts';
import { deserializePresentationRequest } from './deserialize-spec.ts';

export {
  PresentationRequest,
  Presentation,
  type ZkAppInputContext,
  type HttpsInputContext,
};

type BaseInputContext = {
  presentationCircuitVKHash: Field;
  serverNonce: Field;
};

type ZkAppInputContext = BaseInputContext & {
  action: Field;
};

type HttpsInputContext = BaseInputContext & {
  action: string;
};

type BaseWalletContext = {
  clientNonce: Field;
};

type ZkAppWalletContext = BaseWalletContext & {
  verifierIdentity: PublicKey;
};

type HttpsWalletContext = BaseWalletContext & {
  verifierIdentity: string;
};

type PresentationRequestType = 'no-context' | 'zk-app' | 'https';

type PresentationRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = {
  type: PresentationRequestType;
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  deriveContext(walletContext?: ZkAppWalletContext | HttpsWalletContext): Field;
} & (
  | {
      type: 'no-context';
    }
  | {
      type: 'zk-app';
      inputContext: ZkAppInputContext;
    }
  | {
      type: 'https';
      inputContext: HttpsInputContext;
    }
);

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

  zkApp<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>,
    inputContext: ZkAppInputContext
  ): PresentationRequest<Output, Inputs> {
    const { presentationCircuitVKHash, action, serverNonce } = inputContext;
    const claimsType = NestedProvable.fromValue(claims);
    const claimsFields = Struct(claimsType).toFields(claims);
    const claimsHash = Poseidon.hash(claimsFields);

    return {
      type: 'zk-app',
      spec,
      claims,
      inputContext,
      deriveContext: (walletContext: ZkAppWalletContext) => {
        const { verifierIdentity, clientNonce } = walletContext;
        const context = computeContext({
          type: 'zk-app',
          presentationCircuitVKHash,
          clientNonce,
          serverNonce,
          verifierIdentity,
          action,
          claims: claimsHash,
        });
        return generateContext(context);
      },
    };
  },

  https<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>,
    inputContext: HttpsInputContext
  ): PresentationRequest<Output, Inputs> {
    const { presentationCircuitVKHash, action, serverNonce } = inputContext;
    const claimsType = NestedProvable.fromValue(claims);
    const claimsFields = Struct(claimsType).toFields(claims);
    const claimsHash = Poseidon.hash(claimsFields);

    return {
      type: 'https',
      spec,
      claims,
      inputContext,
      deriveContext: (walletContext: HttpsWalletContext) => {
        const { verifierIdentity, clientNonce } = walletContext;
        const context = computeContext({
          type: 'https',
          presentationCircuitVKHash,
          clientNonce,
          serverNonce,
          verifierIdentity,
          action,
          claims: claimsHash,
        });
        return generateContext(context);
      },
    };
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

async function createPresentation<Output, Inputs extends Record<string, Input>>(
  ownerKey: PrivateKey,
  {
    request,
    walletContext,
    credentials,
  }: {
    request: PresentationRequest<Output, Inputs>;
    walletContext?: ZkAppWalletContext | HttpsWalletContext;
    credentials: (StoredCredential & { key?: string })[];
  }
): Promise<Presentation<Output, Inputs>> {
  let context = request.deriveContext(walletContext);
  let { program } = await Presentation.compile(request);

  let credentialsNeeded = Object.entries(request.spec.inputs).filter(
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
