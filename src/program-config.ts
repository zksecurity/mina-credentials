import {
  Bool,
  Bytes,
  Field,
  PublicKey,
  Struct,
  VerificationKey,
  type InferProvable,
  type ProvablePure,
} from 'o1js';

export type { AttestationType };

// dummy attestation with no proof attached
type AttestationNone<DataType extends ProvableType> = {
  type: 'none';
  data: DataType;
};

// recursive proof
type AttestationProof<DataType extends ProvableType> = {
  type: 'proof';
  data: DataType;
  vk: VerificationKey;
};

// native signature
type AttestationSignature<DataType extends ProvableType> = {
  type: 'signature';
  data: DataType;
  issuerPubKey: PublicKey;
};

type BaseData = Record<string, any>;

type AttestationType<DataType extends ProvableType = ProvableType> =
  | AttestationNone<DataType>
  | AttestationProof<DataType>
  | AttestationSignature<DataType>;

type AttestationData<Attestation> = Attestation extends { data: infer Data }
  ? InferProvable<Data>
  : never;

type Tuple<T> = [T, ...T[]] | [];

type Node<Data = any> =
  | AttestationNone<ProvableType<Data>>
  | AttestationProof<ProvableType<Data>>
  | AttestationSignature<ProvableType<Data>>
  | { type: 'constant'; data: ProvableType<Data>; value: Data }
  | { type: 'public'; data: ProvableType<Data> }
  | { type: 'private'; data: ProvableType<Data> }
  | { type: 'property'; key: string; inner: Node }
  | { type: 'equals'; left: Node; right: Node }
  | { type: 'and'; left: Node<Bool>; right: Node<Bool> };

function attestation<DataType extends ProvableType>(
  attestation: AttestationType<DataType>
): Node<InferProvableType<DataType>> {
  return attestation;
}

function constant<DataType extends ProvableType>(
  data: DataType,
  value: InferProvableType<DataType>
): Node<InferProvableType<DataType>> {
  return { type: 'constant', data, value };
}

function publicParameter<DataType extends ProvableType>(
  data: DataType
): Node<InferProvable<DataType>> {
  return { type: 'public', data };
}

function privateParameter<DataType extends ProvableType>(
  data: DataType
): Node<InferProvableType<DataType>> {
  return { type: 'private', data };
}

function property<K extends string, Data extends { [key in K]: any }>(
  node: Node<Data>,
  key: K
): Node<Data[K]> {
  return { type: 'property', key, inner: node as Node<any> };
}

function equals<Data>(left: Node<Data>, right: Node<Data>): Node<Bool> {
  return { type: 'equals', left, right };
}

function and(left: Node<Bool>, right: Node<Bool>): Node<Bool> {
  return { type: 'and', left, right };
}

// TODO remove

const Bytes32 = Bytes(32);

function example() {
  let att = attestation({
    type: 'none',
    data: Struct({ age: Field, name: Bytes32 }),
  });
  let age = property(att, 'age');
  let targetAge = publicParameter(Field);
  let ageEquals = equals(age, targetAge);

  let name = property(att, 'name');
  let targetName = constant(Bytes32, Bytes32.fromString('Alice'));
  let nameEquals = equals(name, targetName);

  let ageAndName = and(ageEquals, nameEquals);
  return ageAndName;
}

console.dir(example(), { depth: null });

// TODO these types should be in o1js

type WithProvable<A> = { provable: A } | A;
type ProvableType<T = any, V = any> = WithProvable<ProvablePure<T, V>>;
type ToProvable<A extends WithProvable<any>> = A extends {
  provable: infer P;
}
  ? P
  : A;
type InferProvableType<T extends ProvableType> = InferProvable<ToProvable<T>>;
