// Verificação de assinatura com Web Crypto (HS*, RS*, PS*, ES256/ES384) e criação de tokens HS256 de teste.
import { JwtError, base64UrlToBytes, bytesToBase64Url, textToBase64Url, formatJson } from './jwt.js';

const encoder = new TextEncoder();

export const ALGORITHMS = {
  HS256: { kind: 'hmac', hash: 'SHA-256' },
  HS384: { kind: 'hmac', hash: 'SHA-384' },
  HS512: { kind: 'hmac', hash: 'SHA-512' },
  RS256: { kind: 'rsa', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  RS384: { kind: 'rsa', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  RS512: { kind: 'rsa', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  PS256: { kind: 'rsa', name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 },
  PS384: { kind: 'rsa', name: 'RSA-PSS', hash: 'SHA-384', saltLength: 48 },
  PS512: { kind: 'rsa', name: 'RSA-PSS', hash: 'SHA-512', saltLength: 64 },
  ES256: { kind: 'ec', name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256', size: 64 },
  ES384: { kind: 'ec', name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384', size: 96 },
};

function getSubtle(subtle) {
  const s = subtle || (globalThis.crypto && globalThis.crypto.subtle);
  if (!s) throw new JwtError('Este navegador não oferece Web Crypto (é preciso abrir a página por HTTPS ou localhost).');
  return s;
}

export function decodeSecret(secret, encoding) {
  if (encoding === 'base64') {
    const compact = String(secret).replace(/\s+/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    try {
      return base64UrlToBytes(compact);
    } catch {
      throw new JwtError('O segredo não é Base64 válido. Troque para «texto» se ele for uma senha comum.');
    }
  }
  return encoder.encode(String(secret));
}

// Lê uma chave PEM e devolve os bytes DER do SPKI.
export function pemToSpki(pem) {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(pem);
  if (!match) throw new JwtError('Não encontrei um bloco PEM completo (-----BEGIN ...----- / -----END ...-----).');
  const label = match[1];
  if (label.includes('PRIVATE KEY')) {
    throw new JwtError('Isso é uma chave privada. Para verificar basta a chave pública, e chaves privadas não devem ser coladas em sites.');
  }
  if (label === 'RSA PUBLIC KEY') {
    throw new JwtError('Chave no formato PKCS#1 (BEGIN RSA PUBLIC KEY). Converta para SPKI (BEGIN PUBLIC KEY) ou use a JWK.');
  }
  if (label === 'CERTIFICATE') {
    throw new JwtError('Certificados X.509 não são aceitos aqui. Cole a chave pública (BEGIN PUBLIC KEY) ou a JWK.');
  }
  if (label !== 'PUBLIC KEY') throw new JwtError(`Bloco PEM do tipo «${label}» não é suportado. Use BEGIN PUBLIC KEY.`);
  const body = match[2].replace(/[\s]/g, '');
  try {
    return base64UrlToBytes(body.replace(/\+/g, '-').replace(/\//g, '_'));
  } catch {
    throw new JwtError('O conteúdo do bloco PEM não é Base64 válido.');
  }
}

export function spkiToPem(der) {
  const b64 = bytesToBase64Url(der).replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  return `-----BEGIN PUBLIC KEY-----\n${padded.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
}

// Escolhe a JWK (de uma JWK solta ou de um JWKS) e devolve só os campos públicos.
export function selectJwk(text, spec, kid) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new JwtError('A chave começa com «{», mas não é um JSON válido.');
  }
  let jwk = parsed;
  if (Array.isArray(parsed.keys)) {
    const keys = parsed.keys.filter((k) => k && typeof k === 'object');
    if (!keys.length) throw new JwtError('O JWKS não tem nenhuma chave.');
    if (kid !== undefined) {
      jwk = keys.find((k) => k.kid === kid);
      if (!jwk) throw new JwtError(`O JWKS não tem chave com kid «${kid}».`);
    } else if (keys.length === 1) {
      jwk = keys[0];
    } else {
      throw new JwtError('O JWKS tem várias chaves e o token não indica o kid. Cole só a chave certa.');
    }
  }
  const wantedKty = spec.kind === 'ec' ? 'EC' : 'RSA';
  if (jwk.kty !== wantedKty) throw new JwtError(`O token usa ${spec.kind === 'ec' ? 'ECDSA' : 'RSA'}, mas a JWK é do tipo «${jwk.kty}».`);
  const hadPrivate = 'd' in jwk;
  if (wantedKty === 'RSA') {
    if (!jwk.n || !jwk.e) throw new JwtError('A JWK RSA precisa dos campos «n» e «e».');
    return { jwk: { kty: 'RSA', n: jwk.n, e: jwk.e }, hadPrivate };
  }
  if (jwk.crv !== spec.namedCurve) throw new JwtError(`O algoritmo pede a curva ${spec.namedCurve}, mas a JWK usa «${jwk.crv}».`);
  if (!jwk.x || !jwk.y) throw new JwtError('A JWK EC precisa dos campos «x» e «y».');
  return { jwk: { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y }, hadPrivate };
}

async function importVerifyKey(subtle, spec, keyText, kid) {
  const text = String(keyText || '').trim();
  if (!text) throw new JwtError('Cole a chave pública (PEM ou JWK) para verificar.');
  const params = spec.kind === 'ec' ? { name: 'ECDSA', namedCurve: spec.namedCurve } : { name: spec.name, hash: spec.hash };
  let notes = [];
  try {
    if (text.startsWith('{')) {
      const { jwk, hadPrivate } = selectJwk(text, spec, kid);
      if (hadPrivate) notes = ['Você colou uma chave privada; só a parte pública foi usada. Evite colar chaves privadas em sites.'];
      return { key: await subtle.importKey('jwk', jwk, params, false, ['verify']), notes };
    }
    if (text.includes('-----BEGIN')) {
      return { key: await subtle.importKey('spki', pemToSpki(text), params, false, ['verify']), notes };
    }
  } catch (err) {
    if (err instanceof JwtError) throw err;
    throw new JwtError(`Não consegui importar a chave. Confira se ela combina com o algoritmo do token (${spec.kind === 'ec' ? `ECDSA ${spec.namedCurve}` : 'RSA'}).`);
  }
  throw new JwtError('Formato de chave não reconhecido. Use PEM (BEGIN PUBLIC KEY) ou JWK.');
}

// decoded: resultado de decodeToken(). keyText: segredo (HS*) ou chave pública (RS*, PS*, ES*).
// Retorna { valid, alg, notes }.
export async function verifySignature(decoded, keyText, { secretEncoding = 'text', subtle } = {}) {
  if (decoded.type !== 'JWS') throw new JwtError('Tokens JWE são criptografados; a verificação aqui é só para tokens assinados (JWS).');
  const alg = decoded.header.alg;
  if (typeof alg === 'string' && alg.toLowerCase() === 'none') throw new JwtError('Este token não tem assinatura (alg: none): não há o que verificar.');
  const spec = ALGORITHMS[alg];
  if (!spec) throw new JwtError(`A verificação de «${alg}» não é suportada aqui. Suportados: ${Object.keys(ALGORITHMS).join(', ')}.`);
  if (!decoded.signatureBytes || !decoded.signatureBytes.length) throw new JwtError('O token não traz assinatura.');
  const s = getSubtle(subtle);
  const data = encoder.encode(decoded.signingInput);
  const signature = decoded.signatureBytes;

  if (spec.kind === 'hmac') {
    const secret = decodeSecret(keyText ?? '', secretEncoding);
    if (!secret.length) throw new JwtError('Informe o segredo para verificar.');
    const key = await s.importKey('raw', secret, { name: 'HMAC', hash: spec.hash }, false, ['verify']);
    return { valid: await s.verify('HMAC', key, signature, data), alg, notes: [] };
  }

  const { key, notes } = await importVerifyKey(s, spec, keyText, decoded.header.kid);
  if (spec.kind === 'ec') {
    if (signature.length !== spec.size) {
      const der = signature[0] === 0x30 ? ' Ela parece estar no formato DER; no JWS a assinatura ECDSA é r||s.' : '';
      return { valid: false, alg, notes: [...notes, `A assinatura tem ${signature.length} bytes; para ${alg} deveriam ser ${spec.size}.${der}`] };
    }
    return { valid: await s.verify({ name: 'ECDSA', hash: spec.hash }, key, signature, data), alg, notes };
  }
  const algorithm = spec.name === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: spec.saltLength } : { name: spec.name };
  return { valid: await s.verify(algorithm, key, signature, data), alg, notes };
}

function parseObject(text, label) {
  formatJson(text, label);
  const value = JSON.parse(text);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new JwtError(`${label} precisa ser um objeto JSON ({ ... }).`);
  return value;
}

// Cria um token HS256 a partir do JSON do cabeçalho e do payload e de um segredo em texto.
export async function signHs256(headerText, payloadText, secret, { subtle } = {}) {
  const header = parseObject(headerText, 'O cabeçalho');
  const payload = parseObject(payloadText, 'O payload');
  if (header.alg !== undefined && header.alg !== 'HS256') {
    throw new JwtError(`Esta aba só cria tokens HS256, mas o cabeçalho pede «${header.alg}».`);
  }
  const secretBytes = encoder.encode(String(secret ?? ''));
  if (!secretBytes.length) throw new JwtError('Informe um segredo.');
  const s = getSubtle(subtle);
  const encodedHeader = textToBase64Url(JSON.stringify({ alg: 'HS256', ...header }));
  const encodedPayload = textToBase64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const key = await s.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = new Uint8Array(await s.sign('HMAC', key, encoder.encode(signingInput)));
  const notes = secretBytes.length < 32
    ? [`O segredo tem ${secretBytes.length} bytes. Para HS256, a RFC 7518 exige uma chave de pelo menos 256 bits (32 bytes).`]
    : [];
  return { token: `${signingInput}.${bytesToBase64Url(signature)}`, notes };
}

export function randomSecret(bytes = 32) {
  const data = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(data);
  return bytesToBase64Url(data);
}
