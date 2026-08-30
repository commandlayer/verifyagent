const KEY_DOCUMENT_SCHEMA = 'commandlayer.receipt-verification-keys.v1';
const RECEIPT_PROFILE = 'commandlayer.execution-evidence.v1';
const DEFAULT_MAX_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 5_000;

function nonEmpty(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function configuredUrl(options = {}) {
  return options.url
    || (typeof process !== 'undefined' ? process.env?.COMMANDLAYER_RECEIPT_KEY_URL : null)
    || null;
}

function validateConfiguredUrl(value) {
  if (!nonEmpty(value)) return null;
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError('factory receipt key URL must be a valid URL');
  }
  if (url.protocol !== 'https:') throw new TypeError('factory receipt key URL must use HTTPS');
  if (url.username || url.password) throw new TypeError('factory receipt key URL must not contain credentials');
  if (url.hash) throw new TypeError('factory receipt key URL must not contain a fragment');
  return url.toString();
}

function unavailable(reason) {
  return { state: 'unavailable', reason, key: null, source: 'not resolved' };
}

function authoritativeFailure(reason) {
  return { state: 'authoritative_failure', reason, key: null, source: 'CommandLayer HTTPS trust root' };
}

function resolved(key) {
  return { state: 'resolved', reason: null, key, source: 'CommandLayer HTTPS trust root' };
}

function contentLength(response) {
  const raw = response?.headers?.get?.('content-length');
  if (!raw) return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function validateDocument(document, { kid, signerId }) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    return authoritativeFailure('ERR_FACTORY_KEY_DOCUMENT_INVALID');
  }
  if (document.schema !== KEY_DOCUMENT_SCHEMA || document.profile !== RECEIPT_PROFILE || !Array.isArray(document.keys)) {
    return authoritativeFailure('ERR_FACTORY_KEY_DOCUMENT_SCHEMA');
  }

  const matches = document.keys.filter((item) => (
    item
    && typeof item === 'object'
    && item.kid === kid
    && item.signer_id === signerId
    && item.alg === 'Ed25519'
    && item.status === 'active'
  ));
  if (matches.length !== 1) {
    return authoritativeFailure(matches.length === 0
      ? 'ERR_FACTORY_KEY_NOT_FOUND'
      : 'ERR_FACTORY_KEY_AMBIGUOUS');
  }

  const match = matches[0];
  if (!nonEmpty(match.public_key_pem)
      || !match.public_key_pem.includes('BEGIN PUBLIC KEY')
      || match.public_key_pem.includes('PRIVATE KEY')) {
    return authoritativeFailure('ERR_FACTORY_PUBLIC_KEY_INVALID');
  }
  return resolved({
    publicKeyPem: match.public_key_pem,
    kid,
    signerId,
  });
}

export async function resolveFactoryKeyFromDocument({ kid, signerId }, options = {}) {
  if (!nonEmpty(kid) || !nonEmpty(signerId)) {
    return authoritativeFailure('ERR_FACTORY_KEY_IDENTITY_REQUIRED');
  }

  const rawUrl = configuredUrl(options);
  if (!rawUrl) return { state: 'disabled', reason: null, key: null, source: 'not configured' };

  let url;
  try {
    url = validateConfiguredUrl(rawUrl);
  } catch {
    return authoritativeFailure('ERR_FACTORY_KEY_URL_INVALID');
  }

  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') return unavailable('ERR_FACTORY_KEY_FETCH_UNAVAILABLE');
  const maxBytes = Number.isFinite(Number(options.maxBytes)) ? Number(options.maxBytes) : DEFAULT_MAX_BYTES;
  const timeoutMs = Number.isFinite(Number(options.timeoutMs)) ? Number(options.timeoutMs) : DEFAULT_TIMEOUT_MS;
  const controller = typeof AbortController === 'function' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), Math.max(1, timeoutMs)) : null;

  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'error',
      headers: { Accept: 'application/json' },
      signal: controller?.signal,
    });
  } catch {
    return unavailable('ERR_FACTORY_KEY_FETCH_FAILED');
  } finally {
    if (timer) clearTimeout(timer);
  }

  if (!response || typeof response.status !== 'number') return unavailable('ERR_FACTORY_KEY_HTTP_INVALID');
  if (response.status < 200 || response.status >= 300) return unavailable(`ERR_FACTORY_KEY_HTTP_${response.status}`);

  const declaredLength = contentLength(response);
  if (declaredLength !== null && declaredLength > maxBytes) {
    return authoritativeFailure('ERR_FACTORY_KEY_DOCUMENT_TOO_LARGE');
  }

  let text;
  try {
    text = await response.text();
  } catch {
    return authoritativeFailure('ERR_FACTORY_KEY_DOCUMENT_READ_FAILED');
  }
  if (new TextEncoder().encode(text).byteLength > maxBytes) {
    return authoritativeFailure('ERR_FACTORY_KEY_DOCUMENT_TOO_LARGE');
  }

  let document;
  try {
    document = JSON.parse(text);
  } catch {
    return authoritativeFailure('ERR_FACTORY_KEY_DOCUMENT_JSON');
  }
  return validateDocument(document, { kid, signerId });
}

export {
  KEY_DOCUMENT_SCHEMA,
  RECEIPT_PROFILE,
  DEFAULT_MAX_BYTES,
  DEFAULT_TIMEOUT_MS,
  validateConfiguredUrl,
  validateDocument,
};
