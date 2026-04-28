import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../../src/canonicalize.js';
import { importPkcs8PrivateKeyFromPem, sha256Hex, signHashHex } from '../../src/crypto.js';
import { canonicalReceiptPayload } from '../../src/verify.js';

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

export async function createSignedReceipt({
  signer = readEnv('CL_RECEIPT_SIGNER', 'runtime.commandlayer.eth'),
  kid = readEnv('CL_KEY_ID', 'vC4WbcNoq2znSCiQ'),
  canonicalId = readEnv('CL_CANONICAL_ID', 'json.sorted_keys.v1'),
  privatePem = readEnv('CL_PRIVATE_KEY_PEM'),
  now = new Date()
} = {}) {
  if (!privatePem) {
    throw new Error('Missing CL_PRIVATE_KEY_PEM. Put a PKCS8 Ed25519 private key in your environment.');
  }

  const receipt = {
    signer,
    verb: 'agent.execute',
    ts: now.toISOString(),
    input: { task: 'summarize', content: 'hello world' },
    output: runSimpleAgent(),
    execution: { runtime: 'wrapped-agent-demo', run_id: `run_${now.getTime()}` }
  };

  const canonicalPayload = canonicalize(canonicalReceiptPayload(receipt));
  const hash = await sha256Hex(canonicalPayload);
  const privateKey = await importPkcs8PrivateKeyFromPem(privatePem);
  const sig = await signHashHex(hash, privateKey);

  return {
    ...receipt,
    metadata: { proof: { canonicalization: canonicalId, hash_sha256: hash } },
    signature: { alg: 'ed25519', kid, sig }
  };
}

async function main() {
  const signedReceipt = await createSignedReceipt();
  const outPath = path.join(__dirname, 'out', 'receipt.json');
  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, JSON.stringify(signedReceipt, null, 2));

  console.log('Agent ran');
  console.log('Receipt created');
  console.log('Verify at https://www.commandlayer.org/verify.html');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
