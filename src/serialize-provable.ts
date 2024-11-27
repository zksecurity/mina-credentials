/**
 * JSON serialization of provable types and values.
 */
import { NestedProvable, type NestedProvablePure } from './nested.ts';
import { array, ProvableType } from './o1js-missing.ts';
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
  Struct,
  type ProvablePure,
} from 'o1js';
import { assert, assertHasMethod, defined } from './util.ts';
import { ProvableFactory, type SerializedFactory } from './provable-factory.ts';
import type { JSONValue } from './types.ts';

export {
  type O1jsTypeName,
  type SerializedType,
  type SerializedValue,
  supportedTypes,
  serializeProvableType,
  serializeProvable,
  serializeNestedProvable,
  serializeNestedProvableValue,
  deserializeProvableType,
  deserializeProvablePureType,
  deserializeProvable,
  deserializeNestedProvable,
  deserializeNestedProvablePure,
  deserializeNestedProvableValue,
  replaceNull,
};

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

type SerializedType =
  | { _type: O1jsTypeName }
  | { _type: 'Struct'; properties: SerializedNestedType }
  | { _type: 'Array'; inner: SerializedType; size: number }
  | { _type: 'Constant'; value: JSONValue }
  | { _type: 'Bytes'; size: number }
  | { _type: 'Proof'; proof: Record<string, any> }
  | { _type: 'String' }
  | SerializedFactory;

type SerializedNestedType =
  | SerializedType
  | { [key: string]: SerializedNestedType };

// SERIALIZE

function serializeProvableType(type: ProvableType<any>): SerializedType {
  let serialized = ProvableFactory.tryToJSON(type);
  if (serialized !== undefined) return serialized;

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
      name: (type as typeof DynamicProof).name,
      publicInput: serializeProvableType(publicInputType),
      publicOutput: serializeProvableType(publicOutputType),
      maxProofsVerified,
      featureFlags: replaceUndefined(featureFlags),
    };
    return { _type: 'Proof', proof };
  }
  let _type = mapProvableTypeToName.get(type);
  if (_type === undefined && (type as any)._isStruct) {
    return serializeStruct(type as Struct<any>);
  }
  if (_type === undefined && (type as any)._isArray) {
    return {
      _type: 'Array',
      inner: serializeProvableType((type as any).innerType),
      size: (type as any).size,
    };
  }
  assert(_type !== undefined, () => {
    console.log('serializeProvableType', type);
    return `serializeProvableType: Unsupported provable type: ${type}`;
  });
  return { _type };
}

type SerializedValue = SerializedType & { value: any };

function serializeProvable(value: any): SerializedType & { value: JSONValue } {
  let typeClass = ProvableType.fromValue(value);
  let serializedType = serializeProvableType(typeClass);

  if (ProvableFactory.isSerialized(serializedType)) {
    let serialized = ProvableFactory.tryValueToJSON(value);
    return defined(serialized);
  }

  switch (serializedType._type) {
    case 'Bytes':
      return { ...serializedType, value: (value as Bytes).toHex() };
    case 'Proof':
      let json = (value as DynamicProof<any, any>).toJSON();
      return { ...serializedType, value: json };
    case 'Array': {
      return {
        ...serializedType,
        value: value.map((x: any) => serializeProvable(x)),
      };
    }
    case 'Struct':
      return {
        ...serializedType,
        value: (typeClass as Struct<any>).toJSON(value),
      };
    case 'Undefined':
      return { ...serializedType, value: null };
    case 'Constant':
      return serializedType;
    case 'String':
      return { ...serializedType, value };
    case 'UInt8':
      return { ...serializedType, value: (value as UInt8).toString() };
    default:
      assertHasMethod(
        value,
        'toJSON',
        `Missing toJSON method for ${serializedType._type}`
      );
      return { ...serializedType, value: value.toJSON() };
  }
}

function serializeStruct(type: Struct<any>): SerializedType {
  let value = type.empty();
  let properties: SerializedNestedType = {};

  for (let key in value) {
    let type = NestedProvable.fromValue(value[key]);
    properties[key] = serializeNestedProvable(type);
  }
  return { _type: 'Struct', properties };
}

function serializeNestedProvable(type: NestedProvable): SerializedNestedType {
  if (ProvableType.isProvableType(type)) {
    return serializeProvableType(type);
  }

  if (typeof type === 'string' || (type as any) === String)
    return { _type: 'String' };

  if (typeof type === 'object' && type !== null) {
    const serializedObject: Record<string, any> = {};
    for (const key of Object.keys(type)) {
      serializedObject[key] = serializeNestedProvable(type[key]!);
    }
    return serializedObject;
  }

  throw Error(`Unsupported type in NestedProvable: ${type}`);
}

function serializeNestedProvableValue(value: any): any {
  let type = NestedProvable.fromValue(value);
  return serializeNestedProvableTypeAndValue({ type, value });
}

function serializeNestedProvableTypeAndValue(t: {
  type: NestedProvable;
  value: any;
}): any {
  if (ProvableType.isProvableType(t.type)) {
    return serializeProvable(t.value);
  }
  if (typeof t.type === 'string' || (t.type as any) === String) return t.value;

  return Object.fromEntries(
    Object.keys(t.type).map((key) => {
      assert(key in t.value, `Missing value for key ${key}`);
      return [
        key,
        serializeNestedProvableTypeAndValue({
          type: (t.type as any)[key],
          value: t.value[key],
        }),
      ];
    })
  );
}

// DESERIALIZE

function deserializeProvableType(type: SerializedType): ProvableType<any> {
  if (ProvableFactory.isSerialized(type)) return ProvableFactory.fromJSON(type);

  if (type._type === 'Constant') {
    return ProvableType.constant((type as any).value);
  }
  if (type._type === 'Bytes') {
    return Bytes(type.size);
  }
  if (type._type === 'Proof') {
    let proof = type.proof;
    let Proof = class extends DynamicProof<any, any> {
      static publicInputType = deserializeProvablePureType(proof.publicInput);
      static publicOutputType = deserializeProvablePureType(proof.publicOutput);
      static maxProofsVerified = proof.maxProofsVerified;
      static featureFlags = replaceNull(proof.featureFlags) as any;
    };
    Object.defineProperty(Proof, 'name', { value: proof.name });
    return Proof;
  }
  if (type._type === 'Struct') {
    let properties = deserializeNestedProvable(type.properties);
    return Struct(properties);
  }
  if (type._type === 'Array') {
    let inner = deserializeProvableType(type.inner);
    return array(inner, type.size);
  }
  if (type._type === 'String') {
    return String as any;
  }
  let result = supportedTypes[type._type];
  assert(result !== undefined, `Unsupported provable type: ${type._type}`);
  return result;
}

function deserializeProvable(json: SerializedValue): any {
  if (ProvableFactory.isSerialized(json))
    return ProvableFactory.valueFromJSON(json);

  let { _type, value } = json;
  switch (_type) {
    case 'Field':
      return Field.fromJSON(value);
    case 'Bool':
      return Bool.fromJSON(value);
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
    case 'Undefined':
      return undefined;
    case 'VerificationKey':
      return VerificationKey.fromJSON(value);
    case 'Bytes':
      let BytesN = deserializeProvableType(json) as typeof Bytes.Base;
      return BytesN.fromHex(value);
    case 'Proof':
      let Proof = deserializeProvableType(json) as typeof DynamicProof;
      // TODO this is a promise, so fails
      return Proof.fromJSON(value);
    case 'Array':
      return (value as any[]).map((v) => deserializeProvable(v));
    case 'Struct':
      let type = deserializeProvableType(json) as Struct<any>;
      return type.fromJSON(value);
    case 'Constant':
      return value;
    case 'String':
      return value;
    default:
      _type satisfies never;
      throw Error(`Unsupported provable type: ${_type}`);
  }
}

function deserializeProvablePureType(type: {
  _type: O1jsTypeName;
}): ProvablePure<any> {
  const provableType = deserializeProvableType(type);
  return provableType as ProvablePure<any>;
}

function deserializeNestedProvable(type: any): NestedProvable {
  if (typeof type === 'object' && type !== null) {
    if ('_type' in type) {
      // basic provable type
      return deserializeProvableType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvable(value);
      }
      return result as NestedProvable;
    }
  }
  throw Error(`Invalid type in NestedProvable: ${type}`);
}

function deserializeNestedProvablePure(type: any): NestedProvablePure {
  if (typeof type === 'object' && type !== null) {
    if ('_type' in type) {
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

function deserializeNestedProvableValue(value: any): any {
  if (typeof value === 'string') return value;

  if (typeof value === 'object' && value !== null) {
    if ('_type' in value) {
      // basic provable type
      return deserializeProvable(value);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (let [key, v] of Object.entries(value)) {
        result[key] = deserializeNestedProvableValue(v);
      }
      return result;
    }
  }

  throw Error(`Invalid nested provable value: ${value}`);
}

function replaceNull(obj: Record<string, any>): Record<string, any> {
  return Object.fromEntries(
    Object.entries(obj).map(([key, value]) => [
      key,
      value === null ? undefined : value,
    ])
  );
}

// `null` is preserved in JSON, but `undefined` is removed
function replaceUndefined(obj: Record<string, any>): Record<string, any> {
  return Object.fromEntries(
    Object.entries(obj).map(([key, value]) => [
      key,
      value === undefined ? null : value,
    ])
  );
}
