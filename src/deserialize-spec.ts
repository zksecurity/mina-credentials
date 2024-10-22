import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  Provable,
  type ProvablePure,
  assert,
} from 'o1js';
import { Input, Node, Operation, Spec } from './program-spec.ts';
import type {
  NestedProvable,
  NestedProvableFor,
  NestedProvablePure,
} from './nested.ts';
import {
  validateSpecHash,
  supportedTypes,
  type O1jsTypeName,
} from './serialize-spec.ts';
import { Credential, type CredentialId } from './credentials.ts';

export {
  deserializeSpec,
  deserializeInputs,
  deserializeInput,
  deserializeNode,
  deserializeProvableType,
  deserializeProvable,
  deserializeNestedProvable,
};

async function deserializeSpec(serializedSpecWithHash: string): Promise<Spec> {
  if (!(await validateSpecHash(serializedSpecWithHash))) {
    throw new Error('Invalid spec hash');
  }

  const { spec: serializedSpec } = JSON.parse(serializedSpecWithHash);
  const parsedSpec = JSON.parse(serializedSpec);
  let inputs = deserializeInputs(parsedSpec.inputs);
  return {
    inputs,
    logic: {
      assert: deserializeNode(inputs, parsedSpec.logic.assert),
      data: deserializeNode(inputs, parsedSpec.logic.data),
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
      return Input.constant(
        deserializeProvableType(input.data),
        deserializeProvable(input.data.type, input.value)
      );
    case 'public':
      return Input.claim(deserializeNestedProvablePure(input.data));
    case 'credential': {
      let id: CredentialId = input.id;
      let data = deserializeNestedProvablePure(input.data);
      switch (id) {
        case 'signature-native':
          return Credential.signatureNative(data);
        case 'none':
          return Credential.none(data);
        case 'proof':
          throw Error('Serializing proof credential is not supported yet');
        default:
          throw Error(`Unsupported credential id: ${id}`);
      }
    }
    default:
      throw Error(`Invalid input type: ${input.type}`);
  }
}

function deserializeNode(input: any, node: any): Node {
  switch (node.type) {
    case 'owner': {
      return {
        type: 'owner',
      };
    }
    case 'issuer': {
      return {
        type: 'issuer',
        credentialKey: node.credentialKey,
      };
    }
    case 'constant':
      return {
        type: 'constant',
        data: deserializeProvable(node.data.type, node.data.value),
      };
    case 'root':
      return { type: 'root', input };
    case 'property':
      return {
        type: 'property',
        key: node.key,
        inner: deserializeNode(input, node.inner),
      };
    case 'equals':
    case 'lessThan':
    case 'lessThanEq':
      return {
        type: node.type,
        left: deserializeNode(input, node.left),
        right: deserializeNode(input, node.right),
      };
    case 'and':
    case 'or':
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return {
        type: node.type,
        left: deserializeNode(input, node.left),
        right: deserializeNode(input, node.right),
      };
    case 'not':
    case 'hash':
      return {
        type: node.type,
        inner: deserializeNode(input, node.inner),
      };
    case 'ifThenElse':
      return {
        type: 'ifThenElse',
        condition: deserializeNode(input, node.condition),
        thenNode: deserializeNode(input, node.thenNode),
        elseNode: deserializeNode(input, node.elseNode),
      };
    case 'record':
      const deserializedData: Record<string, Node> = {};
      for (const [key, value] of Object.entries(node.data)) {
        deserializedData[key] = deserializeNode(input, value);
      }
      return {
        type: 'record',
        data: deserializedData,
      };
    default:
      throw Error(`Invalid node type: ${node.type}`);
  }
}

function deserializeProvableType(type: { type: O1jsTypeName }): Provable<any> {
  let result = supportedTypes[type.type];
  assert(result !== undefined, `Unsupported provable type: ${type.type}`);
  return result;
}

function deserializeProvable(type: string, value: string): any {
  switch (type) {
    case 'Field':
      return Field.fromJSON(value);
    case 'Bool':
      return Bool(value === 'true');
    case 'UInt8':
      return UInt8.fromJSON({ value });
    case 'UInt32':
      return UInt32.fromJSON(value);
    case 'UInt64':
      return UInt64.fromJSON(value);
    case 'PublicKey':
      return PublicKey.fromJSON(value);
    case 'Signature':
      return Signature.fromJSON(value);
    default:
      throw Error(`Unsupported provable type: ${type}`);
  }
}

function deserializeProvablePureType(type: {
  type: O1jsTypeName;
}): ProvablePure<any> {
  const provableType = deserializeProvableType(type);
  return provableType as ProvablePure<any>;
}

function deserializeNestedProvable(type: any): NestedProvable {
  if (typeof type === 'object' && type !== null) {
    if ('type' in type) {
      // basic provable type
      return deserializeProvableType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvable(value);
      }
      return result as NestedProvableFor<any>;
    }
  }
  throw Error(`Invalid type in NestedProvable: ${type}`);
}

function deserializeNestedProvablePure(type: any): NestedProvablePure {
  if (typeof type === 'object' && type !== null) {
    if ('type' in type) {
      // basic provable pure type
      return deserializeProvablePureType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvablePure(value);
      }
      return result as NestedProvablePure;
    }
  }
  throw Error(`Invalid type in NestedProvablePure: ${type}`);
}
