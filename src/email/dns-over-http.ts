/**
 * This entire file was copied and modified from zk-email-verify:
 * https://github.com/zkemail/zk-email-verify
 */
export { resolveDNSHTTP };

// DoH servers list
const DoHServer = {
  // Google Public DNS
  Google: 'https://dns.google/resolve',
  // Cloudflare DNS
  Cloudflare: 'https://cloudflare-dns.com/dns-query',
};

async function resolveDNSHTTP(name: string) {
  let googleResult = await resolveDKIMPublicKey(name, DoHServer.Google);
  if (googleResult === undefined) {
    throw Error('No DKIM record found in Google');
  }

  let regex = /p=([^;]*)/;
  let match = regex.exec(googleResult);
  if (match) {
    let valueAfterP = match[1]; // Extracting the value after p=
    if (valueAfterP === '') {
      throw Error('No DKIM record found in Google (empty p=)');
    }
  }

  let cloudflareResult = await resolveDKIMPublicKey(name, DoHServer.Cloudflare);

  // Log an error if there is a mismatch in the result
  if (googleResult !== cloudflareResult) {
    console.error(
      'DKIM record mismatch between Google and Cloudflare! Using Google result.'
    );
  }
  return googleResult;
}

// DNS response codes
const DoHStatusNoError = 0;

// DNS RR types
const DoHTypeTXT = 16;

/**
 * Resolve DKIM public key from DNS
 *
 * @param name DKIM record name (e.g. 20230601._domainkey.gmail.com)
 * @param dnsServerURL DNS over HTTPS API URL
 * @return DKIM public key or undefined if not found
 */
async function resolveDKIMPublicKey(
  name: string,
  dnsServerURL: string
): Promise<string | undefined> {
  let cleanURL = dnsServerURL;
  if (!cleanURL.startsWith('https://')) {
    cleanURL = `https://${cleanURL}`;
  }
  if (cleanURL.endsWith('/')) {
    cleanURL = cleanURL.slice(0, -1);
  }

  let queryUrl = new URL(cleanURL);
  queryUrl.searchParams.set('name', name);
  queryUrl.searchParams.set('type', DoHTypeTXT.toString());

  let res = await fetch(queryUrl, {
    headers: { accept: 'application/dns-json' },
  });

  if (!res.ok) return undefined;
  let result = await res.json();
  if (!isDoHResponse(result)) return undefined;
  if (result.Status !== DoHStatusNoError) return undefined;

  for (let answer of result.Answer) {
    if (answer.type !== DoHTypeTXT) continue;
    let dkimRecord = answer.data;
    /*
      Remove all double quotes
      Some DNS providers wrap TXT records in double quotes, 
      and others like Cloudflare may include them. According to 
      TXT (potentially multi-line) and DKIM (Base64 data) standards,
      we can directly remove all double quotes from the DKIM public key.
    */
    return dkimRecord.replace(/"/g, '');
  }
  return undefined;
}

function isDoHResponse(res: unknown): res is DoHResponse {
  return (
    typeof res === 'object' &&
    res !== null &&
    'Status' in res &&
    'Answer' in res
  );
}

type DoHResponse = {
  Status: number; // NOERROR - Standard DNS response code (32 bit integer).
  TC: boolean; // Whether the response is truncated
  AD: boolean; // Whether all response data was validated with DNSSEC
  CD: boolean; // Whether the client asked to disable DNSSEC
  Question: Question[];
  Answer: Answer[];
  Comment: string;
};

type Question = {
  name: string; // FQDN with trailing dot
  type: number; // A - Standard DNS RR type. 5:CNAME, 16:TXT
};

type Answer = {
  name: string; // Always matches name in the Question section
  type: number; // A - Standard DNS RR type. 5:CNAME, 16:TXT
  TTL: number; // Record's time-to-live in seconds
  data: string; // Record data
};
