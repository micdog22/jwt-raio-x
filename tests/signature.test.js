import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeToken, textToBase64Url, bytesToBase64Url, JwtError } from '../src/jwt.js';
import { verifySignature, signHs256, pemToSpki, spkiToPem, decodeSecret, randomSecret } from '../src/signature.js';

const { subtle } = globalThis.crypto;
const CLASSIC = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const enc = new TextEncoder();

test('o token clássico é válido com "your-256-bit-secret"', async () => {
  const d = decodeToken(CLASSIC);
  assert.deepEqual(await verifySignature(d, 'your-256-bit-secret'), { valid: true, alg: 'HS256', notes: [] });
  assert.equal((await verifySignature(d, 'outro-segredo')).valid, false);
});

test('segredo em Base64 (padrão e URL)', async () => {
  const secretB64 = Buffer.from('your-256-bit-secret').toString('base64');
  const d = decodeToken(CLASSIC);
  assert.equal((await verifySignature(d, secretB64, { secretEncoding: 'base64' })).valid, true);
  assert.deepEqual([...decodeSecret('+/8=', 'base64')], [0xfb, 0xff]);
  assert.deepEqual([...decodeSecret('-_8', 'base64')], [0xfb, 0xff]);
  assert.throws(() => decodeSecret('não é base64!', 'base64'), /não é Base64 válido/);
  await assert.rejects(verifySignature(d, ''), /Informe o segredo/);
});

test('HS256: assinar e verificar, inclusive com acentos', async () => {
  const { token, notes } = await signHs256('{"alg":"HS256","typ":"JWT"}', '{"sub":"42","nome":"Maria Exemplo","cidade":"São José"}', 'segredo-de-teste-com-mais-de-32-bytes!!');
  assert.deepEqual(notes, []);
  const d = decodeToken(token);
  assert.equal(d.payload.cidade, 'São José');
  assert.equal((await verifySignature(d, 'segredo-de-teste-com-mais-de-32-bytes!!')).valid, true);
  assert.equal((await verifySignature(d, 'segredo-errado')).valid, false);
  // Conteúdo adulterado invalida a assinatura
  const [h, , s] = token.split('.');
  const forged = decodeToken(`${h}.${textToBase64Url('{"sub":"1","nome":"Maria Exemplo","cidade":"São José"}')}.${s}`);
  assert.equal((await verifySignature(forged, 'segredo-de-teste-com-mais-de-32-bytes!!')).valid, false);
});

test('HS256: avisa sobre segredo curto, completa alg e recusa outro algoritmo', async () => {
  const short = await signHs256('{"typ":"JWT"}', '{"a":1}', 'curto');
  assert.match(short.notes[0], /5 bytes.*256 bits/);
  assert.deepEqual(decodeToken(short.token).header, { alg: 'HS256', typ: 'JWT' });
  await assert.rejects(signHs256('{"alg":"RS256"}', '{}', 'x'), /só cria tokens HS256/);
  await assert.rejects(signHs256('{"alg":"HS256"}', '[1]', 'x'), /payload precisa ser um objeto/);
  await assert.rejects(signHs256('{"alg":"HS256"', '{}', 'x'), /cabeçalho não é JSON válido/);
  await assert.rejects(signHs256('{}', '{}', ''), /Informe um segredo/);
});

async function signWith(privateKey, algorithm, header, payload) {
  const input = `${textToBase64Url(JSON.stringify(header))}.${textToBase64Url(JSON.stringify(payload))}`;
  const signature = new Uint8Array(await subtle.sign(algorithm, privateKey, enc.encode(input)));
  return `${input}.${bytesToBase64Url(signature)}`;
}

test('RS256 com chave pública em PEM (SPKI) e em JWK', async () => {
  const pair = await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const token = await signWith(pair.privateKey, { name: 'RSASSA-PKCS1-v1_5' }, { alg: 'RS256', kid: 'chave-1' }, { sub: 'maria' });
  const pem = spkiToPem(new Uint8Array(await subtle.exportKey('spki', pair.publicKey)));
  assert.match(pem, /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----$/);
  const jwk = await subtle.exportKey('jwk', pair.publicKey);
  const d = decodeToken(token);
  assert.equal((await verifySignature(d, pem)).valid, true);
  assert.equal((await verifySignature(d, JSON.stringify(jwk))).valid, true);
  assert.equal((await verifySignature(d, JSON.stringify({ keys: [{ ...jwk, kid: 'outra' }, { ...jwk, kid: 'chave-1' }] }))).valid, true);
  await assert.rejects(verifySignature(d, JSON.stringify({ keys: [{ ...jwk, kid: 'outra' }] })), /sem chave com kid «chave-1»|não tem chave com kid «chave-1»/);

  // JWK privada: usa só a parte pública e avisa
  const privateJwk = await subtle.exportKey('jwk', pair.privateKey);
  const withPrivate = await verifySignature(d, JSON.stringify(privateJwk));
  assert.equal(withPrivate.valid, true);
  assert.match(withPrivate.notes[0], /chave privada/);

  const tampered = decodeToken(token.replace(/\.[^.]+\./, `.${textToBase64Url('{"sub":"admin"}')}.`));
  assert.equal((await verifySignature(tampered, pem)).valid, false);
});

test('PS256 também é verificado', async () => {
  const pair = await subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const token = await signWith(pair.privateKey, { name: 'RSA-PSS', saltLength: 32 }, { alg: 'PS256' }, { sub: '1' });
  const pem = spkiToPem(new Uint8Array(await subtle.exportKey('spki', pair.publicKey)));
  assert.equal((await verifySignature(decodeToken(token), pem)).valid, true);
});

for (const [alg, curve, hash, size] of [['ES256', 'P-256', 'SHA-256', 64], ['ES384', 'P-384', 'SHA-384', 96]]) {
  test(`${alg} (assinatura r||s) com PEM e JWK`, async () => {
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']);
    const token = await signWith(pair.privateKey, { name: 'ECDSA', hash }, { alg }, { sub: 'joão' });
    const d = decodeToken(token);
    assert.equal(d.signatureBytes.length, size);
    const pem = spkiToPem(new Uint8Array(await subtle.exportKey('spki', pair.publicKey)));
    const jwk = await subtle.exportKey('jwk', pair.publicKey);
    assert.equal((await verifySignature(d, pem)).valid, true);
    assert.equal((await verifySignature(d, JSON.stringify(jwk))).valid, true);
    const other = await subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']);
    const otherPem = spkiToPem(new Uint8Array(await subtle.exportKey('spki', other.publicKey)));
    assert.equal((await verifySignature(d, otherPem)).valid, false);
  });
}

test('ES256 com assinatura de tamanho errado (ex.: DER) é rejeitada com explicação', async () => {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const input = `${textToBase64Url('{"alg":"ES256"}')}.${textToBase64Url('{}')}`;
  const der = Uint8Array.from([0x30, 0x44, ...new Uint8Array(68)]);
  const pem = spkiToPem(new Uint8Array(await subtle.exportKey('spki', pair.publicKey)));
  const result = await verifySignature(decodeToken(`${input}.${bytesToBase64Url(der)}`), pem);
  assert.equal(result.valid, false);
  assert.match(result.notes[0], /70 bytes.*64.*DER/);
});

test('erros de chave e de algoritmo têm mensagens claras', async () => {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const token = await signWith(pair.privateKey, { name: 'ECDSA', hash: 'SHA-256' }, { alg: 'ES256' }, {});
  const d = decodeToken(token);
  await assert.rejects(verifySignature(d, ''), /Cole a chave pública/);
  await assert.rejects(verifySignature(d, 'qualquer coisa'), /Formato de chave não reconhecido/);
  await assert.rejects(verifySignature(d, '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----'), /chave privada/);
  await assert.rejects(verifySignature(d, '-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----'), /PKCS#1/);
  await assert.rejects(verifySignature(d, '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'), /Certificados X.509/);
  await assert.rejects(verifySignature(d, '{"kty":"RSA","n":"AQAB","e":"AQAB"}'), /a JWK é do tipo «RSA»/);
  await assert.rejects(verifySignature(d, '{"kty":"EC","crv":"P-384","x":"a","y":"b"}'), /curva P-256/);
  await assert.rejects(verifySignature(d, '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----'), /Não consegui importar a chave/);
  await assert.rejects(verifySignature(d, '{chave'), /não é um JSON válido/);

  const none = decodeToken(`${textToBase64Url('{"alg":"none"}')}.${textToBase64Url('{}')}.`);
  await assert.rejects(verifySignature(none, 'x'), /alg: none/);
  const es512 = decodeToken(`${textToBase64Url('{"alg":"ES512"}')}.${textToBase64Url('{}')}.AAAA`);
  await assert.rejects(verifySignature(es512, 'x'), (err) => err instanceof JwtError && /«ES512» não é suportada/.test(err.message));
  const jwe = decodeToken(`${textToBase64Url('{"alg":"dir","enc":"A128GCM"}')}..a.b.c`);
  await assert.rejects(verifySignature(jwe, 'x'), /JWE/);
});

test('PEM: ida e volta e erros de formato', () => {
  const der = Uint8Array.from({ length: 100 }, (_, i) => i);
  assert.deepEqual(pemToSpki(spkiToPem(der)), der);
  assert.throws(() => pemToSpki('sem pem'), /bloco PEM completo/);
});

test('segredo aleatório tem 32 bytes em Base64URL', () => {
  const a = randomSecret();
  assert.match(a, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(a, randomSecret());
});
