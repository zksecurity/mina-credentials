import http from 'http';
import { URL } from 'url';
import { ZodSchemas } from './schema.ts';
import { Credential } from '../../../src/index.ts';
import { PrivateKey } from 'o1js';

// private key
const privateKey = PrivateKey.fromBase58(
  'EKDsgej3YrJriYnibHcEsJtYmoRsp2mzD2ta98EkvdNNLeXsrNB9'
);

// Helper to read request body
async function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': 'http://localhost:5173',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const server = http.createServer(async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  try {
    const url = new URL(req.url!, `http://${req.headers.host}`);

    // Add CORS headers to all responses
    Object.entries(corsHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    res.setHeader('Content-Type', 'application/json');

    // Issue Credential endpoint
    if (url.pathname === '/issue-credential' && req.method === 'POST') {
      let body = await readBody(req);
      console.log('/issue-credential', body);

      // validate
      ZodSchemas.CredentialData.parse(JSON.parse(body));

      let credential = Credential.sign(privateKey, body);
      let credentialJson = Credential.toJSON(credential);

      res.writeHead(200);
      res.end(credentialJson);
      return;
    }

    // Verify Credential endpoint
    if (url.pathname === '/verify-credential' && req.method === 'POST') {
      let body = await readBody(req);
      let { presentation } = JSON.parse(body);

      // TODO: Add your actual verification logic here
      // For now, just check if it's a valid JSON
      JSON.parse(presentation);

      res.writeHead(200);
      res.end(JSON.stringify({ status: 'ok' }));
      console.log('Verify Credential', presentation);
      return;
    }

    // Handle 404
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not Found' }));
  } catch (error) {
    console.error('Error:', error);
    res.writeHead(400);
    res.end(
      JSON.stringify({
        error: error instanceof Error ? error.message : 'Unknown error',
      })
    );
  }
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
