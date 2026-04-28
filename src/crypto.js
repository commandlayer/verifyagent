const ED25519_DER_PREFIX = '302a300506032b6570032100';

function hexToBytes(hex) {
  const clean = hex.replace(/^0x/, '');
  if (clean.length % 2 !== 0) throw new Error('Invalid hex length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

export function fromBase64(value) {
  return new Uint8Array(Buffer.from(value, 'base64'));
}

export async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(digest));
}

export async function importEd25519PublicKey(base64PublicKey) {
  const raw = fromBase64(base64PublicKey);
  if (raw.length !== 32) {
    throw new Error('Invalid Ed25519 public key length; expected 32 bytes');
  }
  const spki = hexToBytes(ED25519_DER_PREFIX + bytesToHex(raw));
  return crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
}

export async function importPkcs8PrivateKeyFromPem(privateKeyPem) {
  const cleaned = privateKeyPem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s+/g, '');
  const pkcs8 = fromBase64(cleaned);
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
}

export async function signHashHex(hashHex, privateKey) {
  const payload = new TextEncoder().encode(hashHex);
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, payload);
  return toBase64(new Uint8Array(sig));
}

export async function verifyHashHexSignature(hashHex, signatureBase64, publicKey) {
  const payload = new TextEncoder().encode(hashHex);
  let signature;
  try {
    signature = fromBase64(signatureBase64);
  } catch {
    return false;
  }
  return crypto.subtle.verify({ name: 'Ed25519' }, publicKey, signature, payload);
}
