import {
  CircuitString,
  Field,
  InferProvable,
  PublicKey,
  Struct,
  VerificationKey,
  type ProvablePure,
} from 'o1js';

export type { AttestationType };

// dummy attestation with no proof attached
type AttestationNone<DataType extends ProvablePure<any>> = {
  type: 'none';
  data: DataType;
};

// recursive proof
type AttestationProof<DataType extends ProvablePure<any>> = {
  type: 'proof';
  data: DataType;
  vk: VerificationKey;
};

// native signature
type AttestationSignature<DataType extends ProvablePure<any>> = {
  type: 'signature';
  data: DataType;
  issuerPubKey: PublicKey;
};

type BaseData = Record<string, any>;

type AttestationType<DataType extends ProvablePure<any> = ProvablePure<any>> =
  | AttestationNone<DataType>
  | AttestationProof<DataType>
  | AttestationSignature<DataType>;

type AttestationData<Attestation> = Attestation extends { data: infer Data }
  ? InferProvable<Data>
  : never;

type Tuple<T> = [T, ...T[]] | [];

type Node<Data = any> =
  | AttestationNone<ProvablePure<Data>>
  | AttestationProof<ProvablePure<Data>>
  | AttestationSignature<ProvablePure<Data>>
  | { type: 'public'; value: ProvablePure<Data> }
  | { type: 'private'; value: ProvablePure<Data> }
  | { type: 'property'; key: string; inner: Node }
  | { type: 'equals'; left: Node; right: Node }
  | { type: 'and'; left: Node<boolean>; right: Node<boolean> };

function attestation<DataType extends ProvablePure<any>>(
  attestation: AttestationType<DataType>
): Node<InferProvable<DataType>> {
  return attestation;
}
function publicParams<DataType extends ProvablePure<any>>(
  value: DataType
): Node<InferProvable<DataType>> {
  return { type: 'public', value };
}
function privateParams<DataType extends ProvablePure<any>>(
  value: DataType
): Node<InferProvable<DataType>> {
  return { type: 'private', value };
}

function property<K extends string, Data extends { [key in K]: any }>(
  node: Node<Data>,
  key: K
): Node<Data[K]> {
  return { type: 'property', key, inner: node as Node<any> };
}

function equals<Data>(left: Node<Data>, right: Node<Data>): Node<boolean> {
  return { type: 'equals', left, right };
}

function and(left: Node<boolean>, right: Node<boolean>): Node<boolean> {
  return { type: 'and', left, right };
}

// TODO remove

function example() {
  let att = attestation({
    type: 'none',
    data: Struct({ age: Field, name: CircuitString }),
  });
  let age = property(att, 'age');
  let targetAge = publicParams(Field);
  let ageEquals = equals(age, targetAge);

  let name = property(att, 'name');
  let targetName = publicParams(CircuitString);
  let nameEquals = equals(name, targetName);

  let ageAndName = and(ageEquals, nameEquals);
}
