/**
 * This file contains some helpers to wrap zkpass responses in ecdsa credentials.
 *
 * See `ecdsa-credential.test.ts`
 */
import { PublicKey } from 'o1js';
import { DynamicSHA3 } from '../dynamic.ts';
import { assert, ByteUtils, zip } from '../util.ts';
import { EcdsaEthereum, parseSignature } from './ecdsa-credential.ts';

export { ZkPass, type ZkPassResponseItem };

/**
 * Utitilies to help process zkpass responses.
 */
const ZkPass = { importCredential, encodeParameters, genPublicFieldHash };

type Type = 'bytes32' | 'address';

type PublicField = string | ({ [key: string]: PublicField } & { str?: string });

type ZkPassResponseItem = {
  taskId: string;
  publicFields: PublicField[];
  allocatorAddress: string;
  publicFieldsHash: string;
  allocatorSignature: string;
  uHash: string;
  validatorAddress: string;
  validatorSignature: string;
};

async function importCredential(
  owner: PublicKey,
  schema: string,
  response: ZkPassResponseItem,
  log: (msg: string) => void = () => {}
) {
  let publicFieldsHash = ZkPass.genPublicFieldHash(
    response.publicFields
  ).toBytes();

  // validate public fields hash
  assert(
    '0x' + ByteUtils.toHex(publicFieldsHash) === response.publicFieldsHash
  );

  // compute message hash
  let message = ZkPass.encodeParameters(
    ['bytes32', 'bytes32', 'bytes32', 'bytes32'],
    [
      ByteUtils.fromString(response.taskId),
      ByteUtils.fromString(schema),
      ByteUtils.fromHex(response.uHash),
      publicFieldsHash,
    ]
  );

  let { signature, parityBit } = parseSignature(response.validatorSignature);
  let address = ByteUtils.fromHex(response.validatorAddress);

  const maxMessageLength = 128;

  log('Compiling ZkPass credential...');
  await EcdsaEthereum.compileDependencies({ maxMessageLength });

  let EcdsaCredential = await EcdsaEthereum.Credential({ maxMessageLength });

  log('Creating ZkPass credential...');
  let credential = await EcdsaCredential.create({
    owner,
    publicInput: { signerAddress: EcdsaEthereum.Address.from(address) },
    privateInput: { message, signature, parityBit },
  });

  return credential;
}

// Based on the Solidity ABI encoding we have the following definitions for encoding bytes32 and address
// For any ABI value X, we recursively define enc(X), depending on the type of X being
// bytes<M>: enc(X) is the sequence of bytes in X padded with trailing zero-bytes to a length of 32 bytes.
// address: as in the uint160 case
// uint<M>: enc(X) is the big-endian encoding of X, padded on the higher-order (left) side with zero-bytes such that the length is 32 bytes.
// https://docs.soliditylang.org/en/latest/abi-spec.html#formal-specification-of-the-encoding
function encodeParameters(types: Type[], values: Uint8Array[]) {
  let arrays = zip(types, values).map(([type, value]) => {
    if (type === 'bytes32') return ByteUtils.padEnd(value, 32, 0);
    if (type === 'address') return ByteUtils.padStart(value, 32, 0);
    throw Error('unexpected type');
  });
  return ByteUtils.concat(...arrays);
}

// hash used by zkpass to commit to public fields
// FIXME unfortunately this does nothing to prevent collisions -.-
function genPublicFieldHash(publicFields: PublicField[]) {
  let publicData = publicFields.map((item) => {
    if (typeof item === 'object') delete item.str;
    return item;
  });

  let values: string[] = [];

  function recurse(obj: PublicField) {
    if (typeof obj === 'string') {
      values.push(obj);
      return;
    }
    for (let key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (typeof obj[key] === 'object' && obj[key] !== null) {
          recurse(obj[key]); // it's a nested object, so we do it again
        } else {
          values.push(obj[key]!); // it's not an object, so we just push the value
        }
      }
    }
  }
  publicData.forEach((data) => recurse(data));

  let publicFieldStr = values.join('');
  if (publicFieldStr === '') publicFieldStr = '1'; // ??? another deliberate collision

  return DynamicSHA3.keccak256(publicFieldStr);
}
