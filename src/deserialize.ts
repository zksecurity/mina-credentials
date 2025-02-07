import { Claim, Constant, type Input, Spec } from './program-spec.ts';
import { Node } from './operation.ts';
import { validateSpecHash, type SerializedContext } from './serialize.ts';
import { type CredentialType } from './credential.ts';
import { Credential } from './credential-index.ts';
import {
  deserializeNestedProvable,
  deserializeProvable,
  deserializeProvableType,
} from './serialize-provable.ts';

export {
  deserializeSpec,
  deserializeInputs,
  deserializeInput,
  deserializeNode,
  deserializeInputContext,
  convertSpecFromSerializable,
};

function deserializeInputContext(context: null | SerializedContext) {
  if (context === null) return undefined;
  return {
    type: context.type,
    action:
      context.type === 'zk-app'
        ? deserializeProvable({ _type: 'Field', value: context.action.value })
        : context.action,
    serverNonce: deserializeProvable({
      _type: 'Field',
      value: context.serverNonce.value,
    }),
  };
}

async function deserializeSpec(serializedSpecWithHash: string): Promise<Spec> {
  if (!(await validateSpecHash(serializedSpecWithHash))) {
    throw Error('Invalid spec hash');
  }

  const { spec: serializedSpec } = JSON.parse(serializedSpecWithHash);
  return convertSpecFromSerializable(JSON.parse(serializedSpec));
}

function convertSpecFromSerializable(parsedSpec: any): Spec {
  let inputs = deserializeInputs(parsedSpec.inputs);
  return {
    inputs,
    logic: {
      assert: deserializeNode(inputs, parsedSpec.logic.assert),
      outputClaim: deserializeNode(inputs, parsedSpec.logic.outputClaim),
    },
  };
}

function deserializeInputs(inputs: Record<string, any>): Record<string, Input> {
  const result: Record<string, Input> = {};
  for (const [key, value] of Object.entries(inputs)) {
    result[key] = deserializeInput(value);
  }
  return result;
}

function deserializeInput(input: any): Input {
  switch (input.type) {
    case 'constant':
      return Constant(
        deserializeProvableType(input.data),
        deserializeProvable({ ...input.data, value: input.value })
      );
    case 'claim':
      return Claim(deserializeNestedProvable(input.data));
    case 'credential': {
      let credentialType: CredentialType = input.credentialType;
      let data = deserializeNestedProvable(input.data);
      switch (credentialType) {
        case 'simple':
          return Credential.Native(data);
        case 'unsigned':
          return Credential.Unsigned(data);
        case 'recursive':
          let proof = deserializeProvableType(input.witness.proof) as any;
          return Credential.Recursive(proof, data);
        default:
          throw Error(`Unsupported credential id: ${credentialType}`);
      }
    }
    default:
      throw Error(`Invalid input type: ${input.type}`);
  }
}

function deserializeNode(root: any, node: any): Node;
function deserializeNode(
  root: any,
  node: { type: Node['type'] } & Record<string, any>
): Node {
  switch (node.type) {
    case 'constant':
      return {
        type: 'constant',
        data: deserializeProvable(node.data),
      };
    case 'root':
      return { type: 'root', input: root };

    case 'owner':
    case 'credential':
    case 'issuer':
    case 'issuerPublicKey':
    case 'verificationKeyHash':
    case 'publicInput':
      return node as Node;

    case 'property':
      return {
        type: 'property',
        key: node.key,
        inner: deserializeNode(root, node.inner),
      };
    case 'equals':
    case 'lessThan':
    case 'lessThanEq':
      return {
        type: node.type,
        left: deserializeNode(root, node.left),
        right: deserializeNode(root, node.right),
      };
    case 'equalsOneOf': {
      return {
        type: 'equalsOneOf',
        input: deserializeNode(root, node.input),
        options: Array.isArray(node.options)
          ? node.options.map((o) => deserializeNode(root, o))
          : deserializeNode(root, node.options),
      };
    }
    case 'and':
      return {
        type: node.type,
        inputs: node.inputs.map((i: any) => deserializeNode(root, i)),
      };
    case 'or':
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return {
        type: node.type,
        left: deserializeNode(root, node.left),
        right: deserializeNode(root, node.right),
      };
    case 'hash':
      let result: Node = {
        type: node.type,
        inputs: node.inputs.map((i: any) => deserializeNode(root, i)),
      };
      if (node.prefix !== null) result.prefix = node.prefix;
      return result;
    case 'not':
      return {
        type: node.type,
        inner: deserializeNode(root, node.inner),
      };
    case 'ifThenElse':
      return {
        type: 'ifThenElse',
        condition: deserializeNode(root, node.condition),
        thenNode: deserializeNode(root, node.thenNode),
        elseNode: deserializeNode(root, node.elseNode),
      };
    case 'record':
      const deserializedData: Record<string, Node> = {};
      for (const [key, value] of Object.entries(node.data)) {
        deserializedData[key] = deserializeNode(root, value as any);
      }
      return {
        type: 'record',
        data: deserializedData,
      };
    case 'compute':
      throw Error('Not implemented');
    default:
      throw Error(`Invalid node type: ${node.type}`);
  }
}
