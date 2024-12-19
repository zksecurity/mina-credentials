import 'dotenv/config';
import { assert } from '../../../src/index.ts';

export { HOSTNAME };

let hostname = process.env.HOSTNAME;
assert(hostname !== undefined, 'HOSTNAME env is required');
const HOSTNAME = hostname;
