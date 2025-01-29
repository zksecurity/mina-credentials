export { toBase64, fromBase64 };

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function fromBase64(base64: string) {
  base64 = base64.replace(/=/g, '');
  let n = base64.length;
  let rem = n % 4;
  let k = rem && rem - 1; // how many bytes the last base64 chunk encodes
  let m = (n >> 2) * 3 + k; // total encoded bytes

  let encoded = new Uint8Array(n + 3);
  encoder.encodeInto(base64 + '===', encoded);

  for (let i = 0, j = 0; i < n; i += 4, j += 3) {
    let x =
      (lookup(encoded[i]!) << 18) +
      (lookup(encoded[i + 1]!) << 12) +
      (lookup(encoded[i + 2]!) << 6) +
      lookup(encoded[i + 3]!);
    encoded[j] = x >> 16;
    encoded[j + 1] = (x >> 8) & 0xff;
    encoded[j + 2] = x & 0xff;
  }
  return new Uint8Array(encoded.buffer, 0, m);
}

function toBase64(inputBytes: Uint8Array | ArrayBuffer) {
  let bytes = new Uint8Array(inputBytes);
  let m = bytes.length;
  let k = m % 3;
  let n = Math.floor(m / 3) * 4 + (k && k + 1);
  let N = Math.ceil(m / 3) * 4;
  let encoded = new Uint8Array(N);

  for (let i = 0, j = 0; j < m; i += 4, j += 3) {
    let y = (bytes[j]! << 16) + (bytes[j + 1]! << 8) + (bytes[j + 2]! | 0);
    encoded[i] = encodeLookup(y >> 18);
    encoded[i + 1] = encodeLookup((y >> 12) & 0x3f);
    encoded[i + 2] = encodeLookup((y >> 6) & 0x3f);
    encoded[i + 3] = encodeLookup(y & 0x3f);
  }

  let base64 = decoder.decode(new Uint8Array(encoded.buffer, 0, n));
  if (k === 1) base64 += '==';
  if (k === 2) base64 += '=';
  return base64;
}

function lookup(x: number) {
  let b = _lookup[x];
  if (b === undefined) {
    throw Error(`Invalid base64 character: '${String.fromCharCode(x)}'`);
  }
  return b;
}

function encodeLookup(x: number) {
  let b = _encodeLookup[x];
  if (b === undefined) {
    throw Error(`Invalid base64 character: ${x} out of 0..63 range`);
  }
  return b;
}

const alphabet =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const _lookup = Object.fromEntries(
  Array.from(alphabet).map((a, i) => [a.charCodeAt(0), i])
);
_lookup['='.charCodeAt(0)] = 0;
_lookup['-'.charCodeAt(0)] = 62;
_lookup['_'.charCodeAt(0)] = 63;

const _encodeLookup = Object.fromEntries(
  Array.from(alphabet).map((a, i) => [i, a.charCodeAt(0)])
);
