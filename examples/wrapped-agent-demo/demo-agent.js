import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../../src/canonicalize.js';
import { importPkcs8PrivateKeyFromPem, sha256Hex, signHashHex } from '../../src/crypto.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function readEnv(name, fallback = '') {
  return process.env[name] || fallback;
}

function runSimpleAgent() {
  return {
    summary: 'hello world',
    tokens_used: 12
  };
}

async function main() {
  const signer = readEnv('CL_RECEIPT_SIGNER', 'runtime.commandlayer.eth');
  const kid = readEnv('CL_KEY_ID', 'vC4WbcNoq2znSCiQ');
  const canonicalId = readEnv('CL_CANONICAL_ID', 'json.sorted_keys.v1');
  const privatePem = readEnv('CL_PRIVATE_KEY_PEM');

  if (!privatePem) {
    throw new Error('Missing CL_PRIVATE_KEY_PEM. Put a PKCS8 Ed25519 private key in your environment.');
  }

  const receipt = {
    signer,
    verb: 'agent.execute',
    ts: new Date().toISOString(),
    input: { task: 'summarize', content: 'hello world' },
    output: runSimpleAgent(),
    execution: { runtime: 'wrapped-agent-demo', run_id: `run_${Date.now()}` }
  };

  const canonicalPayload = canonicalize(receipt);
  const hash = await sha256Hex(canonicalPayload);
  const privateKey = await importPkcs8PrivateKeyFromPem(privatePem);
  const sig = await signHashHex(hash, privateKey);

  const signedReceipt = {
    ...receipt,
    metadata: { proof: { canonicalization: canonicalId, hash_sha256: hash } },
    signature: { alg: 'ed25519', kid, sig }
  };

  const outPath = path.join(__dirname, 'out', 'receipt.json');
  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, JSON.stringify(signedReceipt, null, 2));

  console.log('Agent ran');
  console.log('Receipt created');
  console.log('Verify at https://www.commandlayer.org/verify.html');
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
