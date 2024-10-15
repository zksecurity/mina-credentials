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
import {
  Attestation,
  AttestationId,
  Input,
  Node,
  Operation,
  Spec,
} from './program-config.ts';
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
  return {
    inputs: deserializeInputs(parsedSpec.inputs),
    logic: {
      assert: deserializeNode(parsedSpec.logic.assert),
      data: deserializeNode(parsedSpec.logic.data),
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
      return Input.public(deserializeNestedProvablePure(input.data));
    case 'private':
      return Input.private(deserializeNestedProvable(input.data));
    case 'attestation': {
      let id: AttestationId = input.id;
      let data = deserializeNestedProvablePure(input.data);
      switch (id) {
        case 'signatureNative':
          return Attestation.signatureNative(data);
        case 'none':
          return Attestation.none(data);
        case 'proof':
          throw new Error('Serializing proof attestation is not supported yet');
        default:
          throw new Error(`Unsupported attestation id: ${id}`);
      }
    }
    default:
      throw new Error(`Invalid input type: ${input.type}`);
  }
}

function deserializeNode(node: any): Node {
  switch (node.type) {
    case 'constant':
      return {
        type: 'constant',
        data: deserializeProvable(node.data.type, node.data.value),
      };
    case 'root':
      return {
        type: 'root',
        input: deserializeInputs(node.input),
      };
    case 'property':
      return {
        type: 'property',
        key: node.key,
        inner: deserializeNode(node.inner),
      };
    case 'equals':
      return Operation.equals(
        deserializeNode(node.left),
        deserializeNode(node.right)
      );
    case 'lessThan':
      return Operation.lessThan(
        deserializeNode(node.left),
        deserializeNode(node.right)
      );
    case 'lessThanEq':
      return Operation.lessThanEq(
        deserializeNode(node.left),
        deserializeNode(node.right)
      );
    case 'and':
      return Operation.and(
        deserializeNode(node.left),
        deserializeNode(node.right)
      );
    default:
      throw new Error(`Invalid node type: ${node.type}`);
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
      throw new Error(`Unsupported provable type: ${type}`);
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
  throw new Error(`Invalid type in NestedProvablePure: ${type}`);
}
