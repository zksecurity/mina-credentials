import {
  Bool,
  Bytes,
  Field,
  PublicKey,
  Signature,
  Struct,
  Undefined,
  type InferProvable,
  type ProvablePure,
} from 'o1js';

/**
 * TODO: program spec must be serializable
 * - can be done by defining an enum of supported base types
 */

export type { AttestationType };

const Undefined_: ProvablePure<undefined> = Undefined;

// TODO export from o1js
const ProvableType = {
  get<A extends WithProvable<any>>(type: A): ToProvable<A> {
    return (
      (typeof type === 'object' || typeof type === 'function') &&
      type !== null &&
      'provable' in type
        ? type.provable
        : type
    ) as ToProvable<A>;
  },
};

/**
 * An attestation is:
 * - a string fully identifying the attestation type
 * - a type for public parameters
 * - a type for private parameters
 * - a type for data -- which is left generic when defining attestation types
 * - a function `verify: (publicInput: Public, privateInput: Private, type: DataType, data: Data)` that asserts the attestation is valid
 */
type Attestation<
  Id extends string,
  PublicType extends ProvableType,
  PrivateType extends ProvableType,
  DataType extends ProvableType
> = {
  type: Id;
  public: PublicType;
  private: PrivateType;
  data: DataType;

  verify(
    publicInput: InferProvableType<PublicType>,
    privateInput: InferProvableType<PrivateType>,
    data: InferProvableType<DataType>
  ): void;
};

function defineAttestation<
  Id extends string,
  PublicType extends ProvableType,
  PrivateType extends ProvableType
>(config: {
  type: Id;
  public: PublicType;
  private: PrivateType;

  verify<DataType extends ProvableType>(
    publicInput: InferProvableType<PublicType>,
    privateInput: InferProvableType<PrivateType>,
    dataType: DataType,
    data: InferProvableType<DataType>
  ): void;
}): <DataType extends ProvableType>(
  data: DataType
) => Attestation<Id, PublicType, PrivateType, DataType> {
  return function attestation(dataType) {
    return {
      type: config.type,
      public: config.public,
      private: config.private,
      data: dataType,
      verify(publicInput, privateInput, data) {
        return config.verify(publicInput, privateInput, dataType, data);
      },
    };
  };
}

// dummy attestation with no proof attached
const ANone = defineAttestation({
  type: 'attestation-none',
  public: PublicKey,
  private: Undefined_,
  verify() {
    // do nothing
  },
});
type AttestationNone<DataType extends ProvableType> = ReturnType<
  typeof ANone<DataType>
>;

// recursive proof
const AProof = defineAttestation({
  type: 'attestation-proof',
  public: PublicKey,
  private: Undefined_,
  verify(pk, proof, type, data) {
    throw new Error('Proof attestation not implemented');
  },
});
type AttestationProof<DataType extends ProvableType> = ReturnType<
  typeof AProof<DataType>
>;

// native signature
const ASignature = defineAttestation({
  type: 'attestation-signature',
  public: PublicKey,
  private: Signature,
  verify(issuerPk, signature, type, data) {
    signature.verify(issuerPk, ProvableType.get(type).toFields(data));
  },
});
type AttestationSignature<DataType extends ProvableType> = ReturnType<
  typeof ASignature<DataType>
>;

type BaseData = Record<string, any>;

type AttestationType<DataType extends ProvableType = ProvableType> =
  | AttestationNone<DataType>
  | AttestationProof<DataType>
  | AttestationSignature<DataType>;

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
  let att = attestation(ASignature(Struct({ age: Field, name: Bytes32 })));

  let age = property(att, 'age');
  let targetAge = publicParameter(Field);
  let ageEquals = equals(age, targetAge);

  let name = property(att, 'name');
  let targetName = constant(Bytes32, Bytes32.fromString('Alice'));
  let nameEquals = equals(name, targetName);

  let ageAndName = and(ageEquals, nameEquals);
  return ageAndName;
}

console.dir(example(), { depth: 5 });

// TODO these types should be in o1js

type WithProvable<A> = { provable: A } | A;
type ProvableType<T = any, V = any> = WithProvable<ProvablePure<T, V>>;
type ToProvable<A extends WithProvable<any>> = A extends {
  provable: infer P;
}
  ? P
  : A;
type InferProvableType<T extends ProvableType> = InferProvable<ToProvable<T>>;
