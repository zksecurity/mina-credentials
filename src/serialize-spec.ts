import {
  NestedProvable,
  type NestedProvableFor,
  type NestedProvablePure,
  type NestedProvablePureFor,
} from './nested.ts';
import { type ProvablePureType, ProvableType } from './o1js-missing.ts';
import { Spec, Input, Node } from './program-config.ts';
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
  Struct,
} from 'o1js';

// Enum of supported o1js base types
const O1jsType = {
  Field: 'Field',
  Bool: 'Bool',
  UInt8: 'UInt8',
  UInt32: 'UInt32',
  UInt64: 'UInt64',
  PublicKey: 'PublicKey',
  Signature: 'Signature',
} as const;

type O1jsTypeName = (typeof O1jsType)[keyof typeof O1jsType];

const supportedTypes: Record<O1jsTypeName, Provable<any>> = {
  [O1jsType.Field]: Field,
  [O1jsType.Bool]: Bool,
  [O1jsType.UInt8]: UInt8,
  [O1jsType.UInt32]: UInt32,
  [O1jsType.UInt64]: UInt64,
  [O1jsType.PublicKey]: PublicKey,
  [O1jsType.Signature]: Signature,
};

function serializeSpec(spec: Spec): string {
  return JSON.stringify(convertSpecToSerializable(spec), null, 2);
}

// TODO: make deterministic
function convertSpecToSerializable(spec: Spec): any {
  return {
    inputs: Object.fromEntries(
      Object.entries(spec.inputs)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, input]) => [key, convertInputToSerializable(input)])
    ),
    logic: {
      assert: convertNodeToSerializable(spec.logic.assert),
      data: convertNodeToSerializable(spec.logic.data),
    },
  };
}

function convertInputToSerializable(input: Input): any {
  if ('type' in Input) {
    switch (input.type) {
      case 'attestation': {
        return {
          type: 'attestation',
          id: input.id,
          public: serializeProvablePureType(input.public),
          private: serializeProvableType(input.private),
          data: serializeNestedProvablePureFor(input.data),
        };
      }
      case 'constant': {
        return {
          type: 'constant',
          data: serializeProvableType(input.data),
          value: input.data,
        };
      }
      case 'public': {
        return {
          type: 'public',
          data: serializeNestedProvablePureFor(input.data),
        };
      }
      case 'private': {
        return {
          type: 'private',
          data: serializeNestedProvableFor(input.data),
        };
      }
    }
  }
  throw new Error('Invalid input type');
}

function convertNodeToSerializable(node: Node): any {
  switch (node.type) {
    case 'constant': {
    }
    case 'root': {
    }
    case 'property': {
    }
    case 'equals': {
    }
    case 'lessThan': {
    }
    case 'lessThanEq': {
    }
    case 'and': {
    }
  }
}

function isStruct(type: ProvableType<any>): type is Struct<any> {
  return '_isStruct' in type && (type as any)._isStruct === true;
}

export function serializeProvableType(type: ProvableType<any>): any {
  // if (isStruct(type)) {
  //   return {
  //     type: 'Struct',
  //     properties: Object.fromEntries(
  //       Object.entries(type)
  //         .sort(([a], [b]) => a.localeCompare(b))
  //         .map(([key, value]) => [key, serializeProvableType(value)])
  //     ),
  //   };
  // }
  for (const [typeName, provableType] of Object.entries(supportedTypes)) {
    if (type === provableType) {
      return { type: typeName };
    }
  }
  throw new Error(`Unsupported provable type: ${type}`);
}

function serializeProvablePureType(type: ProvablePureType): any {
  return serializeProvableType(type);
}

function serializeNestedProvableFor(type: NestedProvableFor<any>): any {}

function serializeNestedProvablePureFor(
  type: NestedProvablePureFor<any>
): any {}
