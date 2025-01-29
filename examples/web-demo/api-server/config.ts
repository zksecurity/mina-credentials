import 'dotenv/config';
import { assert } from '../../../src/index.ts';

export { HOSTNAME, ORIGIN, SERVER_ID, CREDENTIAL_EXPIRY, DATA_PATH };

const SERVER_ID = 'credentials-web-demo-server';

let hostname = process.env.HOSTNAME;
assert(hostname !== undefined, 'HOSTNAME env is required');
const HOSTNAME = hostname;

let origin = process.env.ORIGIN;
assert(origin !== undefined, 'ORIGIN env is required');
const ORIGIN = origin;

// credentials expire after 1 year
const CREDENTIAL_EXPIRY = 365 * 24 * 60 * 60 * 1000;

const DATA_PATH = 'data';
