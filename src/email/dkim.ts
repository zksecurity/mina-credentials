/**
 * Self-contained implementation of DKIM verification.
 * Spec: https://datatracker.ietf.org/doc/html/rfc6376
 *
 * Significant portions are copied and modified from
 * - zk-email-verify: https://github.com/zkemail/zk-email-verify
 * - mailauth: https://github.com/postalsys/mailauth
 */
import { arrayEqual, assert, assertDefined } from '../util.ts';
import { parseDkimHeaders } from './parse-dkim-headers.ts';
import { TupleN } from 'o1js';
import { fromBase64 } from './base64.ts';
import { resolveDNSHTTP } from './dns-over-http.ts';

export { verifyDkim, prepareEmailForVerification, fetchPublicKeyFromDNS };

let dec = new TextDecoder();
let enc = new TextEncoder();

/**
 * Verify DKIM signature on the given email.
 */
async function verifyDkim(email: string) {
  // parse email for verification inputs
  let { canonicalHeader, canonicalBody, dkimHeader } =
    prepareEmailForVerification(email);

  // compute and compare sha256 body hash
  let { bodyHashSpec, bodyHash } = dkimHeader;
  let actualBodyHash = await computeBodyHash(canonicalBody, bodyHashSpec);
  assert(
    arrayEqual(actualBodyHash, fromBase64(bodyHash)),
    'Body hash mismatch'
  );

  // get public key from DNS, verify signature
  assert(dkimHeader.signAlgo === 'rsa', 'Only RSA signature is supported');

  let { publicKey } = await fetchPublicKeyFromDNS(dkimHeader);

  let ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    fromBase64(dkimHeader.signature),
    enc.encode(canonicalHeader)
  );
  assert(ok, 'Signature verification failed');
}

/**
 * Given an email string, extracts email header and body in their
 * canonicalized form and parses the DKIM configuration from the header.
 */
function prepareEmailForVerification(email: string) {
  let emailBytes = enc.encode(email);
  let { headerBytes, bodyBytes } = splitEmail(emailBytes);
  let header = dec.decode(headerBytes);
  let body = dec.decode(bodyBytes);

  // parse and validate headers
  let headers = parseHeaders(header);

  // TODO: is it correct to only allow one DKIM signature?
  let [dkimHeaderRaw, ...others] = headers.filter(
    (h) => h.key === 'dkim-signature'
  );
  assertDefined(dkimHeaderRaw, 'No DKIM signature found');
  assert(others.length === 0, 'Expected at most one DKIM signature');

  let dkimHeaderParsed = parseDkimHeaders(dkimHeaderRaw.line).parsed;
  assertDefined(dkimHeaderParsed, 'Failed to parse DKIM header');

  let dkimHeader = validateDkimHeader(dkimHeaderParsed);

  // canonical body
  let canonicalBody = canonicalizeBody(body, dkimHeader.bodyCanon);

  // canonical header
  let headersToSign = getHeadersToSign(headers, dkimHeader.headerFields);
  let canonicalHeaders = canonicalizeHeader(
    headersToSign,
    dkimHeader.headerCanon
  );
  let canonicalHeader = canonicalHeaders.join('\r\n');
  let canonicalDkimHeader = canonicalHeaders.pop()!;

  return { canonicalHeader, canonicalBody, canonicalDkimHeader, dkimHeader };
}

async function fetchPublicKeyFromDNS({
  selector,
  signingDomain,
}: {
  selector: string;
  signingDomain: string;
}) {
  let dnsName = `${selector}._domainkey.${signingDomain}`;
  let response = await resolveDNSHTTP(dnsName);
  return await extractDnsPublicKey(response);
}

async function computeBodyHash(
  canonicalBody: string,
  spec: { algo: 'sha256' | 'sha1'; maxBodyLength: number | undefined }
) {
  assert(spec.algo !== 'sha1', 'sha1 is not supported');

  // TODO use the maxBodyLength?
  let canonicalBodyBytes = enc.encode(canonicalBody);
  return crypto.subtle.digest('SHA-256', canonicalBodyBytes);
}

/**
 * Find end of the header and split the email into header and body
 */
function splitEmail(emailBytes: Uint8Array) {
  let n = emailBytes.length;
  let headerLength: undefined | number;

  const LF = 0x0a; // \n
  const CR = 0x0d; // \r

  // header ends with either \n\n or \n\r\n
  for (let i = 0; i < n; i++) {
    let b0 = emailBytes[i];
    if (b0 === LF && i > 0) {
      let b1 = emailBytes[i - 1];
      let b2 = emailBytes[i - 2];
      if (b1 === LF || (b1 === CR && b2 === LF)) {
        headerLength = i + 1;
        break;
      }
    }
  }
  assert(headerLength !== undefined, 'No end of header found');

  let headerBytes = emailBytes.subarray(0, headerLength);
  let bodyBytes = emailBytes.subarray(headerLength);
  return { headerBytes, bodyBytes };
}

/**
 * Parse email headers into individual lines with keys.
 *
 * This was copied and modified from zk-email-verify, which copied and modified from mailauth:
 * https://github.com/postalsys/mailauth
 *
 * TODO: where is the spec for this?
 */
function parseHeaders(headerString: string) {
  let rows: string[][] = headerString
    .replace(/[\r\n]+$/, '')
    .split(/\r?\n/)
    .map((row) => [row]);

  // lines that start with any whitespace are collapsed with the previous line
  for (let i = rows.length - 1; i > 0; i--) {
    if (/^\s/.test(rows[i]![0]!)) {
      rows[i - 1] = rows[i - 1]!.concat(rows[i]!);
      rows.splice(i, 1);
    }
  }
  return rows.map((row) => {
    let line = row.join('\r\n');
    let key = line.match(/^[^:]+/) ?? [''];
    let casedKey = key[0].trim();
    return { key: casedKey.toLowerCase(), casedKey, line };
  });
}

/**
 * Validate and extract DKIM header fields after initial parsing
 */
function validateDkimHeader(dkimHeader: ParsedDkimHeader) {
  // validate algorithms
  let algorithm = dkimHeader.a?.value;
  assertString(algorithm, 'Invalid algorithm');
  let [signAlgo, hashAlgo] = TupleN.fromArray(2, algorithm.split('-'));
  signAlgo = signAlgo.toLowerCase().trim();
  hashAlgo = hashAlgo.toLowerCase().trim();
  assertContains(['rsa', 'ed25519'], signAlgo, 'Invalid sign algorithm');
  assertContains(['sha256', 'sha1'], hashAlgo, 'Invalid hash algorithm');

  // validate canonicalization
  let canonicalization = dkimHeader.c?.value;
  assertString(canonicalization, 'Invalid canonicalization');
  let [headerCanon, bodyCanon] = canonicalization.split('/');
  headerCanon = headerCanon?.toLowerCase().trim();
  // if body canonicalization is not set, then defaults to 'simple'
  bodyCanon = (bodyCanon || 'simple').toLowerCase().trim();
  assertContains(['simple', 'relaxed'], headerCanon, 'Invalid header canon');
  assertContains(['simple', 'relaxed'], bodyCanon, 'Invalid body canon');

  // validate max body length and body hash
  let maxBodyLength = dkimHeader.l?.value;
  assert(
    maxBodyLength === undefined ||
      (typeof maxBodyLength === 'number' && !isNaN(maxBodyLength)),
    'Invalid max body length'
  );
  let bodyHashSpec = { algo: hashAlgo, maxBodyLength };

  let bodyHash = dkimHeader.bh?.value;
  assertString(bodyHash, 'Invalid or missing body hash');

  // validate header fields
  let signingHeaderFields = dkimHeader.h?.value;
  assertNonemptyString(
    signingHeaderFields,
    'Invalid or missing signing header fields'
  );
  let headerFields = signingHeaderFields
    .split(':')
    .map((f) => f.trim().toLowerCase());

  // validate signing domain and selector
  let signingDomain = dkimHeader.d?.value;
  let selector = dkimHeader.s?.value;
  assertNonemptyString(signingDomain, 'Invalid signing domain');
  assertNonemptyString(selector, 'Invalid selector');

  // signature value
  let signature = dkimHeader.b?.value;
  assertString(signature, 'Invalid signature');

  return {
    signAlgo,
    hashAlgo,
    headerCanon,
    bodyCanon,
    signingDomain,
    selector,
    bodyHashSpec,
    bodyHash,
    headerFields,
    signature,
  };
}

type ParsedDkimHeader = {
  a?: { value: unknown };
  c?: { value: unknown };
  d?: { value: unknown };
  s?: { value: unknown };
  bh?: { value: unknown };
  l?: { value: unknown };
  h?: { value: unknown };
  b?: { value: unknown };
  // v?: { value: unknown };
  // t?: { value: unknown };
};

function canonicalizeBody(s: string, canonicalization: 'simple' | 'relaxed') {
  switch (canonicalization) {
    case 'simple':
      return canonicalizeBodySimple(s);
    case 'relaxed':
      return canonicalizeBodyRelaxed(s);
  }
}

/**
 * The "relaxed" body canonicalization algorithm MUST apply the
 * following steps (a) and (b) in order:
 *
 * a. Reduce whitespace:
 * - Ignore all whitespace at the end of lines.  Implementations
 *   MUST NOT remove the CRLF at the end of the line.
 * - Reduce all sequences of WSP within a line to a single SP character.
 *
 * b. Ignore all empty lines at the end of the message body.  "Empty
 * line" is defined in Section 3.4.3.  If the body is non-empty but
 * does not end with a CRLF, a CRLF is added.  (For email, this is
 * only possible when using extensions to SMTP or non-SMTP transport
 * mechanisms.)
 */
function canonicalizeBodyRelaxed(s: string) {
  // NOTE: This section assumes that the message is already in "network
  // normal" format (text is ASCII encoded, lines are separated with CRLF
  // characters, etc.)
  let lines = normalizeLineBreaks(s).split(/\r\n/);

  // a. Reduce whitespace
  lines = lines.map((line) => line.trimEnd().replace(/\s+/g, ' '));

  // b. Ignore all empty lines at the end of the message body
  while (lines.length > 0 && lines[lines.length - 1] === '') {
    lines.pop();
  }

  // Implementations MUST NOT remove the CRLF at the end of the line.
  // If the body is non-empty but does not end with a CRLF, a CRLF is added.
  return lines.join('\r\n') + '\r\n';
}

/**
 * The "simple" body canonicalization algorithm ignores all empty lines
 * at the end of the message body.  An empty line is a line of zero
 * length after removal of the line terminator.  If there is no body or
 * no trailing CRLF on the message body, a CRLF is added.
 */
function canonicalizeBodySimple(s: string) {
  // same as relaxed but without changing whitespace within lines
  let lines = normalizeLineBreaks(s).split(/\r\n/);
  while (lines.length > 0 && lines[lines.length - 1] === '') {
    lines.pop();
  }
  return lines.join('\r\n') + '\r\n';
}

function canonicalizeHeader(
  headers: string[],
  canonicalization: 'simple' | 'relaxed'
) {
  // no changes at all for simple canonicalization
  if (canonicalization === 'simple') return headers;
  return headers.map(canonicalizeHeaderLineRelaxed);
}

function canonicalizeHeaderLineRelaxed(line: string) {
  // 3.4.2
  return (
    line
      // unfold continuation lines
      .replace(/\r?\n/g, '')
      // keys to lowercase, trim around :
      .replace(/^([^:]*):\s*/, (m, k) => k.toLowerCase().trim() + ':')
      // single WSP
      .replace(/\s+/g, ' ')
      .trim()
  );
}

/**
 * Sole \r and \n are normalized to \r\n
 */
function normalizeLineBreaks(s: string) {
  return s.replace(/\r(?!\n)|(?<!\r)\n/g, '\r\n');
}

/**
 * Returns header lines to sign, in the correct order.
 *
 * See 3.5, h= tag on non-existent headers and case-insensivity
 * See 5.4.2 for treatment of duplicate headers
 */
function getHeadersToSign(
  inputHeaders: { key: string; line: string }[],
  headerFields: string[]
) {
  // we find each correct header field starting from the bottom of the header!
  let unusedHeaders = [...inputHeaders];
  let headers: string[] = [];

  for (let field of headerFields) {
    let i = unusedHeaders.findLastIndex((h) => h.key === field);
    // non-existent headers have to be ignored i.e. treated as an empty string
    if (i === -1) continue;
    headers.push(unusedHeaders[i]!.line);
    unusedHeaders.splice(i, 1);
  }

  // replace "b=<...>" with "b=" in the signature header
  let sig = unusedHeaders.find((h) => h.key === 'dkim-signature');
  assertDefined(sig, 'No DKIM signature header found');
  let signatureHeader = sig.line.replace(/([;:\s]+b=)[^;]+/, (_, p1) => p1);

  // signature header must not be included in the signed header fields so far
  // it's appended at the end instead (without the actual signature)
  assert(!headerFields.includes('dkim-signature'), 'Invalid header fields');
  headers.push(signatureHeader);

  // header fields must include "from"
  assert(headerFields.includes('from'), 'Invalid header fields (missing from)');

  return headers;
}

/**
 * Extract public key from DNS TXT record
 *
 * This was copied and modified from zk-email-verify, which copied and modified from mailauth:
 * https://github.com/postalsys/mailauth
 */
async function extractDnsPublicKey(s: string) {
  let rr = s.replaceAll(/\s+/g, '').replaceAll('"', '');

  let entry = parseDkimHeaders(rr).parsed;
  assertDefined(entry, 'Failed to parse public key response');

  let publicKeyBase64 = entry.p?.value;
  let keyVersion = entry.v?.value;
  let keyType = entry.k?.value;

  assertNonemptyString(publicKeyBase64, 'Invalid public key value');
  assertNonemptyString(keyVersion, 'Invalid key version');
  assertNonemptyString(keyType, 'Invalid key type');

  assert(keyVersion.toLowerCase() === 'dkim1', 'Invalid key version');
  assert(keyType.toLowerCase() === 'rsa', 'Key type must be RSA');

  let publicKeyBytesDer = fromBase64(publicKeyBase64);

  let publicKey = await crypto.subtle.importKey(
    'spki',
    publicKeyBytesDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  let modulusLength = (publicKey.algorithm as { modulusLength?: number })
    .modulusLength;
  assert(
    modulusLength !== undefined && modulusLength >= 1024,
    `Invalid public key length: ${modulusLength}`
  );
  return { publicKey, publicKeyBytesDer, modulusLength };
}

function assertString(
  value: unknown,
  message: string
): asserts value is string {
  assert(typeof value === 'string', message);
}
function assertNonemptyString(
  value: unknown,
  message: string
): asserts value is string {
  assert(typeof value === 'string' && value !== '', message);
}

function assertContains<const T extends any[]>(
  arr: T,
  value: unknown,
  message: string
): asserts value is T[number] {
  assert(arr.includes(value), message);
}
