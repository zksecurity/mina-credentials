import { Spec, type Input } from './program-spec.ts';
import { Node } from './operation.ts';
import {
  type HttpsInputContext,
  type ZkAppInputContext,
} from './presentation.ts';
import {
  type SerializedValue,
  serializeNestedProvable,
  serializeProvable,
  serializeProvableType,
} from './serialize-provable.ts';
import { assert, mapObject } from './util.ts';
import { Credential } from './credential-index.ts';
import type { InputJSON } from './validation.ts';

export {
  type SerializedValue,
  type SerializedContext,
  serializeNode,
  serializeInput,
  convertSpecToSerializable,
  serializeSpec,
  validateSpecHash,
  serializeInputContext,
};

async function serializeSpec(spec: Spec): Promise<string> {
  const serializedSpec = JSON.stringify(convertSpecToSerializable(spec));
  const hash = await hashSpec(serializedSpec);
  return JSON.stringify({ spec: serializedSpec, hash });
}

function convertSpecToSerializable(spec: Spec): Record<string, any> {
  return {
    inputs: mapObject(spec.inputs, (input) => serializeInput(input)),
    assert: serializeNode(spec.assert),
    outputClaim: serializeNode(spec.outputClaim),
  };
}

function serializeInput(input: Input): InputJSON {
  switch (input.type) {
    case 'constant': {
      return {
        type: 'constant',
        data: serializeProvableType(input.data),
        value: serializeProvable(input.value).value,
      };
    }
    case 'claim': {
      return {
        type: 'claim',
        data: serializeNestedProvable(input.data),
      };
    }
    default: {
      assert('credentialType' in input, 'Invalid input type');
      return Credential.specToJSON(input);
    }
  }
}

function serializeNode(node: Node): object {
  switch (node.type) {
    case 'constant': {
      return {
        type: 'constant',
        data: serializeProvable(node.data),
      };
    }
    case 'root': {
      return { type: 'root' };
    }
    case 'owner':
    case 'credential':
    case 'issuer':
    case 'issuerPublicKey':
    case 'verificationKeyHash':
    case 'publicInput':
      return node;

    case 'property': {
      return {
        type: 'property',
        key: node.key,
        inner: serializeNode(node.inner),
      };
    }
    case 'and':
      return {
        type: node.type,
        inputs: node.inputs.map(serializeNode),
      };
    case 'equals':
    case 'lessThan':
    case 'lessThanEq':
    case 'or':
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return {
        type: node.type,
        left: serializeNode(node.left),
        right: serializeNode(node.right),
      };
    case 'equalsOneOf': {
      return {
        type: 'equalsOneOf',
        input: serializeNode(node.input),
        options: Array.isArray(node.options)
          ? node.options.map(serializeNode)
          : serializeNode(node.options),
      };
    }
    case 'hash':
      return {
        type: node.type,
        inputs: node.inputs.map(serializeNode),
        prefix: node.prefix ?? null,
      };
    case 'not':
      return {
        type: node.type,
        inner: serializeNode(node.inner),
      };
    case 'ifThenElse':
      return {
        type: 'ifThenElse',
        condition: serializeNode(node.condition),
        thenNode: serializeNode(node.thenNode),
        elseNode: serializeNode(node.elseNode),
      };
    case 'record': {
      const serializedData: Record<string, any> = {};
      for (const [key, value] of Object.entries(node.data)) {
        serializedData[key] = serializeNode(value);
      }
      return {
        type: 'record',
        data: serializedData,
      };
    }
    case 'compute':
      throw Error('Cannot serialize compute node');
    default:
      node satisfies never;
      throw Error(`Invalid node type: ${(node as Node).type}`);
  }
}

type SerializedContext =
  | { type: 'https'; action: string; serverNonce: SerializedValue }
  | { type: 'zk-app'; action: SerializedValue; serverNonce: SerializedValue };

function serializeInputContext(
  context: undefined | ZkAppInputContext | HttpsInputContext
): null | SerializedContext {
  if (context === undefined) return null;

  let serverNonce = serializeProvable(context.serverNonce);

  switch (context.type) {
    case 'zk-app':
      let action = serializeProvable(context.action);
      return { type: context.type, serverNonce, action };
    case 'https':
      return { type: context.type, serverNonce, action: context.action };
    default:
      throw Error(`Unsupported context type: ${(context as any).type}`);
  }
}

async function hashSpec(serializedSpec: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(serializedSpec);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function validateSpecHash(
  serializedSpecWithHash: string
): Promise<boolean> {
  const { spec, hash } = JSON.parse(serializedSpecWithHash);
  const recomputedHash = await hashSpec(spec);
  return hash === recomputedHash;
}
