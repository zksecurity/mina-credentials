import { DynamicSHA3 } from '../dynamic.ts';
import { ByteUtils, zip } from '../util.ts';

export { encodeParameters, genPublicFieldHash, type ResponseItem };

type Type = 'bytes32' | 'address';

type PublicField = string | ({ [key: string]: PublicField } & { str?: string });

type ResponseItem = {
  taskId: string;
  publicFields: PublicField[];
  allocatorAddress: string;
  publicFieldsHash: string;
  allocatorSignature: string;
  uHash: string;
  validatorAddress: string;
  validatorSignature: string;
};

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
