import { Claim, Constant, type Input, Spec } from './program-spec.ts';
import { Node } from './operation.ts';
import { type SerializedContext } from './serialize-spec.ts';
import { Credential } from './credential-index.ts';
import {
  deserializeNestedProvable,
  deserializeProvable,
  deserializeProvableType,
} from './serialize-provable.ts';
import type { InputJSON, NodeJSON, SpecJSON } from './validation.ts';
import { mapObject } from './util.ts';

export {
  deserializeSpec,
  deserializeInput,
  deserializeNode,
  deserializeInputContext,
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

function deserializeSpec(parsedSpec: SpecJSON): Spec {
  let inputs = mapObject(parsedSpec.inputs, (input) => deserializeInput(input));
  return {
    inputs,
    assert: deserializeNode(inputs, parsedSpec.assert),
    outputClaim: deserializeNode(inputs, parsedSpec.outputClaim),
  };
}

function deserializeInput(input: InputJSON): Input {
  let type = input.type;
  switch (input.type) {
    case 'constant':
      return Constant(
        deserializeProvableType(input.data),
        deserializeProvable({ ...input.data, value: input.value })
      );
    case 'claim':
      return Claim(deserializeNestedProvable(input.data));
    case 'credential': {
      return Credential.specFromJSON(input);
    }
    default:
      throw Error(`Invalid input type: ${type}`);
  }
}

function deserializeNode(root: any, node: NodeJSON): Node {
  let type = node.type;
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
    default:
      node satisfies never;
      throw Error(`Invalid node type: ${type}`);
  }
}
