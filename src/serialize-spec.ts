import { Spec, Input, Node } from './program-config';
import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  Provable,
} from 'o1js';

// Enum of supported o1js base types
enum O1jsType {
  Field = 'Field',
  Bool = 'Bool',
  UInt8 = 'UInt8',
  UInt32 = 'UInt32',
  UInt64 = 'UInt64',
  PublicKey = 'PublicKey',
  Signature = 'Signature',
}

const supportedTypes: Record<O1jsType, Provable<any>> = {
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

function convertSpecToSerializable(spec: Spec): any {
  return {
    inputs: Object.fromEntries(
      Object.entries(spec.inputs).map(([key, input]) => [
        key,
        convertInputToSerializable(input),
      ])
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
      }
      case 'constant': {
      }
      case 'public': {
      }
      case 'private': {
      }
    }
  }
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
