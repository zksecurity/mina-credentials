import {
  Bytes,
  createEcdsa,
  createForeignCurve,
  Crypto,
  EcdsaSignature,
  Field,
  type From,
  Keccak,
  Provable,
  Unconstrained,
} from 'o1js';
import { Credential } from '../credential-index.ts';
import { DynamicSHA3, DynamicString } from '../dynamic.ts';
import { bytesToBigintBE } from '../rsa/utils.ts';
import { assert, ByteUtils } from '../util.ts';
import { unpackBytes } from '../credentials/gadgets.ts';

export { EcdsaEthereum, parseSignature, recoverPublicKey, publicKeyToAddress };

class PublicKey extends createForeignCurve(Crypto.CurveParams.Secp256k1) {}
class Signature extends createEcdsa(PublicKey) {}

const Bytes32 = Bytes(32);
const Address = Bytes(20);

const EcdsaEthereum = {
  Signature,
  PublicKey,
  Credential: EcdsaCredential,
};

// Ethereum signed message hash (EIP-191), assuming a 32-byte message that resulted from another hash
const MESSAGE_PREFIX = '\x19Ethereum Signed Message:\n32';

function EcdsaCredential({ maxMessageLength }: { maxMessageLength: number }) {
  const Message = DynamicString({ maxLength: maxMessageLength });
  return Credential.Recursive.fromMethod(
    {
      name: `ecdsa-${maxMessageLength}`,
      publicInput: { signerAddress: Address },
      privateInput: {
        message: Message,
        signature: Signature,
        parityBit: Unconstrained.withEmpty(false),
      },
      data: { message: Message },
    },
    async ({
      publicInput: { signerAddress: address },
      privateInput: { message, signature, parityBit },
    }) => {
      // TODO recursive proof of this
      let messageHash = Provable.witness(Bytes32, () =>
        DynamicSHA3.keccak256(message)
      );
      let finalHash = Keccak.ethereum([
        ...Bytes.fromString(MESSAGE_PREFIX).bytes,
        ...messageHash.bytes,
      ]);

      // witness the recovered public key
      let publicKey = Provable.witness(PublicKey, () =>
        recoverPublicKey(finalHash, signature, parityBit.get())
      );

      // check that public key hashes to address
      let recoveredAddress = publicKeyToAddress(publicKey);
      Provable.assertEqual(Address, recoveredAddress, address);

      // verify the signature against the now-validated public key
      signature.verifySignedHash(finalHash, publicKey);
      return { message };
    }
  );
}

function publicKeyToAddress(pk: From<typeof PublicKey>) {
  let { x, y } = PublicKey.from(pk);

  // convert both x and y to 32-byte big-endian integers
  let xBytes = foreignFieldToBytes32BE(x);
  let yBytes = foreignFieldToBytes32BE(y);

  // hash the concatenation of x and y
  // and take the last 20 bytes as the address
  let pkHash = Keccak.ethereum([...xBytes, ...yBytes]);
  return Address.from(pkHash.bytes.slice(-20));
}

/**
 * Convert 3x88-bit foreign field to 32 big-endian bytes.
 * Asserts that the 33th byte is zero.
 */
function foreignFieldToBytes32BE(field: { value: [Field, Field, Field] }) {
  let [x0, x1, x2] = field.value;
  let bytes0 = unpackBytes(x0, 11);
  let bytes1 = unpackBytes(x1, 11);
  let bytes2 = unpackBytes(x2, 11);
  let extraByte = bytes2.pop()!;
  extraByte.assertEquals(0, 'Foreign field exceeds 32 bytes');
  // since big-endian is expected, we reverse the bytes
  return [...bytes0, ...bytes1, ...bytes2].reverse();
}

/**
 * Recover the implied public key from a message hash, signature and a parity bit.
 */
function recoverPublicKey(
  messageHash: Bytes | Uint8Array,
  signature: From<typeof EcdsaSignature>,
  isOdd: boolean
) {
  let {
    Scalar: { Bigint: Scalar },
    Field: { Bigint: Field },
    Bigint: Curve,
  } = EcdsaEthereum.PublicKey;

  // read inputs
  if (messageHash instanceof Bytes.Base) messageHash = messageHash.toBytes();
  if (!(signature instanceof EcdsaEthereum.Signature))
    signature = EcdsaEthereum.Signature.from(signature);

  let m = Scalar.mod(bytesToBigintBE(messageHash));
  let r = signature.r.toBigInt();
  let s = signature.s.toBigInt();

  // first, recover R_y from R_x and parity
  let x = Field.mod(r);
  let x3 = Field.mul(x, Field.square(x));
  let y2 = Field.add(x3, Field.mul(Curve.a, x) + Curve.b);
  let y = Field.sqrt(y2);
  assert(y !== undefined);
  if (Field.isEven(y) !== !isOdd) y = Field.negate(y);
  let R = { x, y, infinity: false };

  // recover public key
  let rInv = Scalar.inverse(r);
  assert(rInv !== undefined);

  let publicKey = Curve.sub(
    Curve.scale(R, Scalar.mul(s, rInv)),
    Curve.scale(Curve.one, Scalar.mul(m, rInv))
  );
  assert(publicKey.infinity === false);
  return publicKey;
}

/**
 * Input can be a hex string or a Uint8Array.
 */
function parseSignature(signature: string | Uint8Array) {
  if (typeof signature === 'string') signature = ByteUtils.fromHex(signature);
  assert(signature.length === 65);

  let r = bytesToBigintBE(signature.slice(0, 32));
  let s = bytesToBigintBE(signature.slice(32, 64));
  let v = signature[64]!;
  assert(v === 27 || v === 28, `Invalid recovery id "v" ${v}`);

  // Convert v to parity of R_y (27/28 -> 0/1 -> boolean)
  let isOdd = !!(v - 27);
  return { signature: { r, s }, isOdd };
}
