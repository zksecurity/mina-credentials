import { NestedProvable } from './nested.ts';
import { ProvableType } from './o1js-missing.ts';
import { Spec, type Input, Node } from './program-spec.ts';
import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  Undefined,
  Bytes,
  DynamicProof,
  VerificationKey,
} from 'o1js';
import { assert } from './util.ts';

// Supported o1js base types
const supportedTypes = {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  Undefined,
  VerificationKey,
};
type O1jsTypeName = keyof typeof supportedTypes;

let mapProvableTypeToName = new Map<ProvableType<any>, O1jsTypeName>();
for (let [key, value] of Object.entries(supportedTypes)) {
  mapProvableTypeToName.set(value, key as O1jsTypeName);
}

export {
  type O1jsTypeName,
  type SerializedProvableType,
  supportedTypes,
  serializeProvableType,
  serializeProvable,
  serializeNestedProvable,
  serializeNode,
  serializeInputs,
  serializeInput,
  convertSpecToSerializable,
  serializeSpec,
  validateSpecHash,
};

async function serializeSpec(spec: Spec): Promise<string> {
  const serializedSpec = JSON.stringify(convertSpecToSerializable(spec));
  const hash = await hashSpec(serializedSpec);
  return JSON.stringify({ spec: serializedSpec, hash });
}

function convertSpecToSerializable(spec: Spec): Record<string, any> {
  return {
    inputs: serializeInputs(spec.inputs),
    logic: {
      assert: serializeNode(spec.logic.assert),
      data: serializeNode(spec.logic.data),
    },
  };
}

function serializeInputs(inputs: Record<string, Input>): Record<string, any> {
  return Object.fromEntries(
    // sort by keys so we always get the same serialization for the same spec
    // will be important for hashing
    Object.entries(inputs)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([key, input]) => [key, serializeInput(input)])
  );
}

function serializeInput(input: Input): any {
  if ('type' in input) {
    switch (input.type) {
      case 'credential': {
        return {
          type: 'credential',
          id: input.id,
          witness: serializeNestedProvable(input.witness),
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
      case 'claim': {
        return {
          type: 'public',
          data: serializeNestedProvable(input.data),
        };
      }
    }
  }
  throw new Error('Invalid input type');
}

function serializeNode(node: Node): any {
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
    case 'constant': {
      return {
        type: 'constant',
        data: serializeProvable(node.data),
      };
    }
    case 'root': {
      return { type: 'root' };
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
    case 'hash':
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
  }
}

type SerializedProvableType =
  | { _type: O1jsTypeName }
  | { _type: 'Struct' } // TODO
  | { _type: 'Constant'; size: number }
  | { _type: 'Bytes'; size: number }
  | { _type: 'Proof'; proof: Record<string, any> };

function serializeProvableType(
  type: ProvableType<any>
): SerializedProvableType {
  if ('serialize' in type && typeof type.serialize === 'function') {
    return type.serialize();
  }
  if ((type as any).prototype instanceof Bytes.Base) {
    return { _type: 'Bytes', size: (type as typeof Bytes.Base).size };
  }
  if ((type as any).prototype instanceof DynamicProof) {
    let { publicInputType, publicOutputType, maxProofsVerified, featureFlags } =
      type as typeof DynamicProof;
    let proof = {
      publicInput: serializeProvableType(publicInputType),
      publicOutput: serializeProvableType(publicOutputType),
      maxProofsVerified,
      featureFlags,
    };
    return { _type: 'Proof', proof };
  }
  // TODO: handle case when type is a Struct
  if ((type as any)._isStruct) {
    return { _type: 'Struct' };
  }
  let _type = mapProvableTypeToName.get(type);
  assert(
    _type !== undefined,
    `serializeProvableType: Unsupported provable type: ${type}`
  );
  return { _type };
}

function serializeProvable(value: any): { _type: string; value: string } {
  let typeClass = ProvableType.fromValue(value);
  let { _type } = serializeProvableType(typeClass);
  if (_type === 'Bytes') return { _type, value: (value as Bytes).toHex() };
  switch (typeClass) {
    case Bool: {
      return { _type, value: value.toJSON().toString() };
    }
    case UInt8: {
      return { _type, value: value.toJSON().value };
    }
    default: {
      return { _type, value: value.toJSON() };
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
