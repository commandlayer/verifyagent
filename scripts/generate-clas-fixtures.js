import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../src/canonicalize.js';
import { importPkcs8PrivateKeyFromPem, sha256Hex, signHashHex } from '../src/crypto.js';
import { canonicalReceiptPayload } from '../src/verify.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const examplesDir = path.join(repoRoot, 'examples');

const signer = 'runtime.commandlayer.eth';
const kid = 'vC4WbcNoq2znSCiQ';
const privatePem = `-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICwCOgkg9CJs1VC8V718RCXRff/++wAxOdGINZ9mz2Db\n-----END PRIVATE KEY-----`;

async function signReceipt(receipt) {
  const canonical = canonicalize(canonicalReceiptPayload(receipt));
  const hash = await sha256Hex(canonical);
  const privateKey = await importPkcs8PrivateKeyFromPem(privatePem);
  const sig = await signHashHex(hash, privateKey);
  return {
    ...receipt,
    metadata: { proof: { canonicalization: 'json.sorted_keys.v1', hash_sha256: hash } },
    signature: { alg: 'ed25519', kid, sig }
  };
}

async function main() {
  const base = {
    signer,
    ts: '2026-04-29T01:32:57.167Z',
    input: { task: 'summarize', content: 'hello world' },
    output: { summary: 'hello world', tokens_used: 12 },
    execution: { runtime: 'wrapped-agent-demo', run_id: 'run_1777426377167' }
  };

  const sample = await signReceipt({ ...base, verb: 'agent.execute' });
  const sampleTampered = structuredClone(sample);
  sampleTampered.output.summary = 'hello world (tampered)';

  const clasValid = await signReceipt({ ...base, family: 'trust-verification', version: '1.0.0', verb: 'verify' });
  const clasTampered = structuredClone(clasValid);
  clasTampered.output.summary = 'hello world (tampered)';

  await fs.writeFile(path.join(examplesDir, 'sample-receipt.json'), JSON.stringify(sample, null, 2) + '\n');
  await fs.writeFile(path.join(examplesDir, 'tampered-receipt.json'), JSON.stringify(sampleTampered, null, 2) + '\n');
  await fs.writeFile(path.join(examplesDir, 'clas-valid-receipt.json'), JSON.stringify(clasValid, null, 2) + '\n');
  await fs.writeFile(path.join(examplesDir, 'clas-tampered-receipt.json'), JSON.stringify(clasTampered, null, 2) + '\n');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
