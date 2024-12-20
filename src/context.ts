import { Field, Bytes, Poseidon, Hash } from 'o1js';
import { prefixes } from './constants.ts';

export { computeContext, generateContext };

type ContextType = 'zk-app' | 'https';

type BaseContext = {
  type: ContextType;
  vkHash: Field;
  clientNonce: Field;
  serverNonce: Field;
  claims: Field;
  verifierIdentity: string;
};

type ZkAppContext = BaseContext & {
  type: 'zk-app';
  action: Field;
};

type HttpsContext = BaseContext & {
  type: 'https';
  action: string;
};

type Context = ZkAppContext | HttpsContext;

type ContextOutput = {
  type: ContextType;
  vkHash: Field;
  nonce: Field;
  verifierIdentity: Bytes;
  action: Field | Bytes;
  claims: Field;
};

function computeNonce(serverNonce: Field, clientNonce: Field): Field {
  return Poseidon.hashWithPrefix(prefixes.nonce, [serverNonce, clientNonce]);
}

function computeContext(input: Context): ContextOutput {
  const nonce = computeNonce(input.serverNonce, input.clientNonce);
  const type = input.type;

  const verifierIdentity = Hash.Keccak256.hash(
    Bytes.fromString(input.verifierIdentity)
  );

  const action =
    type === 'zk-app'
      ? input.action
      : Hash.Keccak256.hash(Bytes.fromString(input.action));

  const context: ContextOutput = {
    type,
    vkHash: input.vkHash,
    nonce,
    verifierIdentity,
    action,
    claims: input.claims,
  };

  return context;
}

function generateContext(input: ContextOutput): Field {
  const prefix = `${prefixes.context}:${input.type}`;

  const verifierIdentity = input.verifierIdentity.toFields().flat();

  const action =
    input.type === 'zk-app'
      ? [input.action as Field]
      : input.action.toFields().flat();

  const context = Poseidon.hashWithPrefix(prefix, [
    input.vkHash,
    input.nonce,
    ...verifierIdentity,
    ...action,
    input.claims,
  ]);

  return context;
}
