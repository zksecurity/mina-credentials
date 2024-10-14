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
} from 'o1js';
import { Attestation, Input, Node, Spec } from './program-config.ts';
import type {
  NestedProvable,
  NestedProvableFor,
  NestedProvablePureFor,
} from './nested.ts';

export {
  deserializeSpec,
  deserializeInputs,
  deserializeInput,
  deserializeNode,
  deserializeProvableType,
  deserializeProvable,
  deserializeNestedProvableFor,
};

function deserializeSpec(serializedSpec: string): Spec {
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
      return Input.public(deserializeNestedProvablePureFor(input.data));
    case 'private':
      return Input.private(deserializeNestedProvableFor(input.data));
    case 'attestation':
      return Attestation[input.id as keyof typeof Attestation](
        deserializeNestedProvablePureFor(input.data)
      );
    default:
      throw new Error(`Invalid input type: ${input.type}`);
  }
}

function deserializeNode(node: any): Node {}

function deserializeProvableType(type: { type: string }): Provable<any> {
  switch (type.type) {
    case 'Field':
      return Field;
    case 'Bool':
      return Bool;
    case 'UInt8':
      return UInt8;
    case 'UInt32':
      return UInt32;
    case 'UInt64':
      return UInt64;
    case 'PublicKey':
      return PublicKey;
    case 'Signature':
      return Signature;
    default:
      throw new Error(`Unsupported provable type: ${type.type}`);
  }
}

function deserializeProvable(type: string, value: string): any {
  switch (type) {
    case 'Field':
      return Field(value);
    case 'Bool':
      return Bool(value === 'true');
    case 'UInt8':
      return UInt8.fromJSON({ value });
    case 'UInt32':
      return UInt32.from(value);
    case 'UInt64':
      return UInt64.from(value);
    case 'PublicKey':
      return PublicKey.fromBase58(value);
    case 'Signature':
      return Signature.fromBase58(value);
    default:
      throw new Error(`Unsupported provable type: ${type}`);
  }
}

function deserializeProvablePureType(type: {
  type: string;
}): ProvablePure<any> {
  const provableType = deserializeProvableType(type);
  if (provableType === Signature) {
    throw new Error('Signature is not a ProvablePure type');
  }
  return provableType as ProvablePure<any>;
}

function deserializeNestedProvableFor(type: any): NestedProvableFor<any> {
  if (typeof type === 'object' && type !== null) {
    if ('type' in type) {
      // basic provable type
      return deserializeProvableType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvableFor(value);
      }
      return result as NestedProvableFor<any>;
    }
  }
  throw new Error(`Invalid type in NestedProvableFor: ${type}`);
}

function deserializeNestedProvablePureFor(
  type: any
): NestedProvablePureFor<any> {
  if (typeof type === 'object' && type !== null) {
    if ('type' in type) {
      // basic provable pure type
      return deserializeProvablePureType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvablePureFor(value);
      }
      return result as NestedProvablePureFor<any>;
    }
  }
  throw new Error(`Invalid type in NestedProvablePureFor: ${type}`);
}
