import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  Struct,
  Poseidon,
  Provable,
} from 'o1js';
import { Input, Node, Spec, Attestation } from './program-config.ts';
import { NestedProvable } from './nested.ts';

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

function deserializeInputs(
  inputs: Record<string, any>
): Record<string, Input> {}

function deserializeInput(input: any): Input {}

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

function deserializeNestedProvableFor(type: any): NestedProvable {}
