import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeToken, cleanTokenInput, base64UrlToBytes, bytesToBase64Url, textToBase64Url, formatJson, tokensToText, JwtError,
} from '../src/jwt.js';

const CLASSIC = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

test('decodifica o token clássico', () => {
  const d = decodeToken(CLASSIC);
  assert.equal(d.type, 'JWS');
  assert.deepEqual(d.header, { alg: 'HS256', typ: 'JWT' });
  assert.deepEqual(d.payload, { sub: '1234567890', name: 'John Doe', iat: 1516239022 });
  assert.equal(d.signature, 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
  assert.equal(d.signatureBytes.length, 32);
  assert.equal(d.signingInput, CLASSIC.split('.').slice(0, 2).join('.'));
  assert.equal(tokensToText(d.payloadFormatted.tokens), '{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022\n}');
});

test('aceita "Bearer", aspas e quebras de linha em volta do token', () => {
  assert.equal(cleanTokenInput(`  Bearer ${CLASSIC}\n`), CLASSIC);
  assert.equal(cleanTokenInput(`Authorization: Bearer ${CLASSIC}`), CLASSIC);
  assert.equal(cleanTokenInput(`"${CLASSIC}"`), CLASSIC);
  assert.equal(cleanTokenInput(CLASSIC.replace('.', '.\n  ')), CLASSIC);
  assert.deepEqual(decodeToken(`bearer ${CLASSIC}`).payload.name, 'John Doe');
});

test('payload UTF-8 com acentos', () => {
  const payload = { name: 'João Ação', cidade: 'São Paulo', emoji: '🇧🇷' };
  const token = `${textToBase64Url('{"alg":"HS256"}')}.${textToBase64Url(JSON.stringify(payload))}.`;
  const d = decodeToken(token);
  assert.deepEqual(d.payload, payload);
  assert.equal(d.signatureBytes, null);
  // Base64URL dos bytes UTF-8 (não de Latin-1)
  assert.equal(textToBase64Url('ã'), 'w6M');
  assert.deepEqual([...base64UrlToBytes('w6M')], [0xc3, 0xa3]);
});

test('Base64URL ida e volta, com e sem preenchimento', () => {
  for (let n = 0; n < 40; n++) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
    const encoded = bytesToBase64Url(bytes);
    assert.ok(!/[+/=]/.test(encoded));
    assert.deepEqual(base64UrlToBytes(encoded), bytes);
  }
  assert.deepEqual([...base64UrlToBytes('YQ==')], [0x61]);
  assert.deepEqual([...base64UrlToBytes('-_8')], [0xfb, 0xff]);
});

test('tokens malformados geram mensagens claras', () => {
  const cases = [
    ['', /Cole um token/],
    ['abc', /3 partes.*Este tem 1/],
    ['a.b', /Este tem 2/],
    ['a.b.c.d', /Este tem 4/],
    ['ab*c.eyJ9.x', /cabeçalho contém caracteres que não pertencem ao Base64URL/],
    ['eyJhbGciOiJIUzI1NiJ9+.e30.x', /Base64URL/],
    ['a.e30.x', /tamanho impossível/],
    [`${textToBase64Url('{"alg":')}.e30.x`, /cabeçalho não é JSON válido: terminou antes do esperado/],
    [`${textToBase64Url('[1,2]')}.e30.x`, /cabeçalho precisa ser um objeto JSON/],
    [`${bytesToBase64Url(Uint8Array.from([0xff, 0xfe, 0x7b]))}.e30.x`, /não é texto UTF-8 válido/],
    [`.e30.x`, /cabeçalho está vazio/],
    [`${textToBase64Url('{"alg":"HS256"}')}.e30.x*y`, /assinatura contém caracteres/],
  ];
  for (const [token, message] of cases) {
    assert.throws(() => decodeToken(token), (err) => err instanceof JwtError && message.test(err.message), `token ${JSON.stringify(token)}`);
  }
});

test('payload que não é JSON é mostrado como texto', () => {
  const d = decodeToken(`${textToBase64Url('{"alg":"HS256"}')}.${textToBase64Url('olá, mundo')}.`);
  assert.equal(d.payloadIsJson, false);
  assert.equal(d.payloadText, 'olá, mundo');
  assert.match(d.payloadFormatted.error, /não é JSON válido/);
});

test('JWE (5 partes): só o cabeçalho é decodificado', () => {
  const header = textToBase64Url('{"alg":"RSA-OAEP","enc":"A256GCM"}');
  const d = decodeToken(`${header}.chave.iv.texto-cifrado.tag`);
  assert.equal(d.type, 'JWE');
  assert.deepEqual(d.header, { alg: 'RSA-OAEP', enc: 'A256GCM' });
});

test('formatJson preserva números exatos, aninha e detecta chaves repetidas', () => {
  const { tokens, duplicates } = formatJson('{"id":12345678901234567890,"a":{"b":[1,{"c":true}],"b":null},"x":-1.5e3,"a":"z","s":"\\u00e3\\n"}');
  assert.equal(
    tokensToText(tokens),
    '{\n  "id": 12345678901234567890,\n  "a": {\n    "b": [\n      1,\n      {\n        "c": true\n      }\n    ],\n    "b": null\n  },\n  "x": -1.5e3,\n  "a": "z",\n  "s": "\\u00e3\\n"\n}',
  );
  assert.deepEqual(duplicates, ['a.b', 'a']);
  assert.deepEqual(tokens.slice(0, 3).map((t) => t.type), ['punct', 'space', 'key']);
  assert.equal(tokensToText(formatJson('{}').tokens), '{}');
  assert.equal(tokensToText(formatJson(' [ ] ').tokens), '[]');
});

test('formatJson recusa JSON inválido com a posição do erro', () => {
  assert.throws(() => formatJson('{"a":1,}'), /esperava o nome de um campo entre aspas \(posição 8\)/);
  assert.throws(() => formatJson('{"a" 1}'), /esperava «:»/);
  assert.throws(() => formatJson('{"a":01}'), /esperava «,» ou «}»/);
  assert.throws(() => formatJson('{"a":"\\x"}'), /escape inválido/);
  assert.throws(() => formatJson('{"a":"\u0001"}'), /caractere de controle/);
  assert.throws(() => formatJson('{"a":tru}'), /valor inesperado «t»/);
  assert.throws(() => formatJson('{} {}'), /conteúdo depois do fim/);
  assert.throws(() => formatJson('['.repeat(20000)), /níveis demais|terminou antes/);
});
