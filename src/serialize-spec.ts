import { NestedProvable } from './nested.ts';
import { ProvableType } from './o1js-missing.ts';
import { Spec, Input, Node } from './program-spec.ts';
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

// Supported o1js base types
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

let mapProvableTypeToName = new Map<ProvableType<any>, string>();
for (let [key, value] of Object.entries(supportedTypes)) {
  mapProvableTypeToName.set(value, key);
}

export {
  type O1jsTypeName,
  supportedTypes,
  serializeProvableType,
  serializeProvable,
  serializeNestedProvable,
  serializeNode,
  serializeInput,
  convertSpecToSerializable,
  serializeSpec,
  validateSpecHash,
};

// TODO: simplify and unify serialization
// like maybe instead of data: {type: 'Field'} it can be data: 'Field' idk, will figure out
// TODO: Bytes?
async function serializeSpec(spec: Spec): Promise<string> {
  const serializedSpec = JSON.stringify(convertSpecToSerializable(spec));
  const hash = await hashSpec(serializedSpec);
  return JSON.stringify({ spec: serializedSpec, hash });
}

function convertSpecToSerializable(spec: Spec): Record<string, any> {
  return {
    inputs: Object.fromEntries(
      // sort by keys so we always get the same serialization for the same spec
      // will be important for hashing
      Object.entries(spec.inputs)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([key, input]) => [key, serializeInput(input)])
    ),
    logic: {
      assert: serializeNode(spec.logic.assert),
      data: serializeNode(spec.logic.data),
    },
  };
}

function serializeInput(input: Input): any {
  if ('type' in input) {
    switch (input.type) {
      case 'credential': {
        return {
          type: 'credential',
          id: input.id,
          public: serializeProvableType(input.public),
          private: serializeProvableType(input.private),
          data: serializeNestedProvable(input.data),
        };
      }
      case 'constant': {
        return {
          type: 'constant',
          data: serializeProvableType(input.data),
          value: serializeProvable(input.value).value,
        };
      }
      case 'public': {
        return {
          type: 'public',
          data: serializeNestedProvable(input.data),
        };
      }
      case 'private': {
        return {
          type: 'private',
          data: serializeNestedProvable(input.data),
        };
      }
    }
  }
  throw new Error('Invalid input type');
}

function serializeNode(node: Node): any {
  switch (node.type) {
    case 'constant': {
      return {
        type: 'constant',
        data: serializeProvable(node.data),
      };
    }
    case 'root': {
      return {
        type: 'root',
        input: Object.fromEntries(
          // sort by keys so we always get the same serialization for the same spec
          // will be important for hashing
          Object.entries(node.input)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([key, input]) => [key, serializeInput(input)])
        ),
      };
    }
    case 'property': {
      return {
        type: 'property',
        key: node.key,
        inner: serializeNode(node.inner),
      };
    }
    case 'equals':
    case 'lessThan':
    case 'lessThanEq':
    case 'and':
      return {
        type: node.type,
        left: serializeNode(node.left),
        right: serializeNode(node.right),
      };
  }
}

function serializeProvableType(type: ProvableType<any>): Record<string, any> {
  // TODO: handle case when type is a Struct
  const typeName = mapProvableTypeToName.get(type);
  if (typeName === undefined) {
    throw Error(`serializeProvableType: Unsupported provable type: ${type}`);
  }
  return { type: typeName };
}

function serializeProvable(value: any): {
  type: O1jsTypeName;
  value: string;
} {
  let typeClass = ProvableType.fromValue(value);
  let { type } = serializeProvableType(typeClass);
  switch (typeClass) {
    case Bool: {
      return { type: type, value: value.toJSON().toString() };
    }
    case UInt8: {
      return { type: type, value: value.toJSON().value };
    }
    default: {
      return { type: type, value: value.toJSON() };
    }
  }
}

function serializeNestedProvable(type: NestedProvable): Record<string, any> {
  if (ProvableType.isProvableType(type)) {
    return serializeProvableType(type);
  }

  if (typeof type === 'object' && type !== null) {
    const serializedObject: Record<string, any> = {};
    // sort by keys so we always get the same serialization for the same spec
    // will be important for hashing
    for (const [key, value] of Object.entries(type).sort((a, b) =>
      a[0].localeCompare(b[0])
    )) {
      serializedObject[key] = serializeNestedProvable(value);
    }
    return serializedObject;
  }

  throw new Error(`Unsupported type in NestedProvable: ${type}`);
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
