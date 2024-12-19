import { PrivateKey, PublicKey } from 'o1js';
import { dataFromInput, ZodSchemas } from './schema.ts';
import { Credential } from '../../../src/index.ts';

const privateKey = PrivateKey.fromBase58(
  'EKDsgej3YrJriYnibHcEsJtYmoRsp2mzD2ta98EkvdNNLeXsrNB9'
);

const ownerBase58 = 'B62qirEU67oGjJosXtgoGeAKLwuDKA8g1mm5U2V1nfHgdo5a6SAcsMj';
const data = dataFromInput({
  name: 'Gregor Mitscha-Baude',
  nationality: 'Austria',
  birthDate: 548035200000,
  id: 'e9c6e526748bf0755c2ea275ab6c7da4',
  expiresAt: 1766102400000,
});
const credentialData = {
  owner: PublicKey.fromBase58(ownerBase58),
  data,
};

let body = Credential.dataToJSON(credentialData);

let body_ = JSON.stringify({
  owner: {
    _type: 'PublicKey',
    value: 'B62qirEU67oGjJosXtgoGeAKLwuDKA8g1mm5U2V1nfHgdo5a6SAcsMj',
  },
  data: {
    nationality: 'Austria',
    name: 'Gregor Mitscha-Baude',
    birthDate: { _type: 'UInt64', value: '548035200000' },
    id: { _type: 'Bytes', size: 16, value: '008f964baa0d69207e3ab5e7d4525564' },
    expiresAt: { _type: 'UInt64', value: '1766102400000' },
  },
});

ZodSchemas.CredentialData.parse(JSON.parse(body));

let credential = Credential.sign(privateKey, body);
let credentialJson = Credential.toJSON(credential);
