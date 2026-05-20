import http from 'node:http';
import * as runtimeCore from '@commandlayer/runtime-core';
import { verifyReceipt } from '../src/verify.js';

const signer = 'runtime.commandlayer.eth';
const kid = 'local-runtime-e2e-kid';
const canonicalization = runtimeCore.CANONICAL_METHOD;
const signatureAlg = runtimeCore.SIGNATURE_ALG;
const hashAlg = 'sha-256';

async function startRuntimeSignServer() {
  const { privateKeyPem: privatePem, ensPubValue } = await runtimeCore.generateEd25519KeyPair();

  const ensRecords = {
    'cl.receipt.signer': signer,
    'cl.sig.kid': kid,
    'cl.sig.pub': ensPubValue,
    'cl.sig.canonical': canonicalization
  };

  const server = http.createServer(async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/runtime/sign') {
      res.writeHead(404).end();
      return;
    }

    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', async () => {
      const payload = JSON.parse(body);
      const signed = await runtimeCore.signCommandLayerReceipt(payload, {
        signer,
        kid,
        privateKeyPem: privatePem,
        canonicalization,
        timestamp: new Date('2026-05-20T00:00:00.000Z').toISOString(),
        metadata: {
          proof: {
            hash: { alg: hashAlg },
            signature: { alg: signatureAlg }
          }
        }
      });

      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(signed));
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port, ensRecords };
}

const payload = {
  signer,
  verb: 'respond',
  ts: '2026-05-20T00:00:00.000Z',
  input: { prompt: 'Verify runtime MCP proof path' },
  output: { summary: 'Runtime produced canonical signed receipt' },
  execution: { duration_ms: 12, model: 'local-runtime' }
};

const { server, port, ensRecords } = await startRuntimeSignServer();

try {
  const response = await fetch(`http://127.0.0.1:${port}/runtime/sign`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });

  const receipt = await response.json();
  console.log('STEP 1 SIGNED');

  const verified = await verifyReceipt(receipt, {
    ens: { textResolver: async (_name, key) => ensRecords[key] || null }
  });
  if (verified.status !== 'VERIFIED') throw new Error('Expected runtime receipt to verify');
  console.log('STEP 2 VERIFIED');

  const tampered = structuredClone(receipt);
  tampered.output.summary = 'Tampered runtime output';
  const invalid = await verifyReceipt(tampered, {
    ens: { textResolver: async (_name, key) => ensRecords[key] || null }
  });
  if (invalid.status !== 'INVALID') throw new Error('Expected tampered runtime receipt to invalidate');
  console.log('STEP 3 TAMPERED INVALID');
} finally {
  server.close();
}
