import 'dotenv/config';
import { assert } from '../../../src/index.ts';

export { HOSTNAME, SERVER_ID };

const SERVER_ID = 'credentials-web-demo-server';

let hostname = process.env.HOSTNAME;
assert(hostname !== undefined, 'HOSTNAME env is required');
const HOSTNAME = hostname;
