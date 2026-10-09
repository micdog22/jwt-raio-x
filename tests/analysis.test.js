import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeToken, textToBase64Url } from '../src/jwt.js';
import { analyzeToken, formatSpan, describeTime, findSensitiveData, isValidCpf, describeClaims } from '../src/analysis.js';

const NOW = 1_760_000_000; // instante fixo para os testes
const DAY = 86400;

function tokenFor(payload, header = { alg: 'HS256', typ: 'JWT' }) {
  const p = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return `${textToBase64Url(JSON.stringify(header))}.${textToBase64Url(p)}.c2lnbmF0dXJh`;
}

const codes = (payload, header, now = NOW) => analyzeToken(decodeToken(tokenFor(payload, header)), { now }).warnings.map((w) => w.code);

test('frases relativas de tempo', () => {
  assert.equal(describeTime('exp', NOW + 2 * 3600, NOW), 'expira em 2 h');
  assert.equal(describeTime('exp', NOW - 3 * DAY, NOW), 'expirou há 3 dias');
  assert.equal(describeTime('exp', NOW - DAY - 5, NOW), 'expirou há 1 dia');
  assert.equal(describeTime('nbf', NOW + 600, NOW), 'passa a valer em 10 min');
  assert.equal(describeTime('iat', NOW - 45, NOW), 'emitido há 45 s');
  assert.equal(describeTime('iat', NOW + 120, NOW), 'emitido no futuro (daqui a 2 min)');
  assert.equal(describeTime('exp', NOW, NOW), 'expira agora');
  assert.equal(formatSpan(65 * DAY), '2 meses');
  assert.equal(formatSpan(31 * DAY), '1 mês');
  assert.equal(formatSpan(800 * DAY), '2 anos');
  assert.equal(formatSpan(-(2 * 3600 + 3599)), '2 h');
});

test('token válido e bem formado não gera alertas', () => {
  assert.deepEqual(codes({ sub: '42', iat: NOW - 60, exp: NOW + 3600 }), []);
});

test('alg none e cabeçalho sem alg', () => {
  assert.ok(codes({ exp: NOW + 60 }, { alg: 'none' }).includes('alg-none'));
  assert.ok(codes({ exp: NOW + 60 }, { alg: 'NONE' }).includes('alg-none'));
  assert.ok(codes({ exp: NOW + 60 }, { typ: 'JWT' }).includes('no-alg'));
});

test('sem exp, expirado, validade longa, ainda não válido e iat no futuro', () => {
  assert.deepEqual(codes({ sub: '1' }), ['no-exp']);
  assert.deepEqual(codes({ exp: NOW - 3 * DAY, iat: NOW - 4 * DAY }), ['expired']);
  assert.deepEqual(codes({ exp: NOW }), ['expired']);
  assert.deepEqual(codes({ iat: NOW, exp: NOW + 31 * DAY }), ['long-validity']);
  assert.deepEqual(codes({ iat: NOW, exp: NOW + 30 * DAY }), []);
  assert.deepEqual(codes({ exp: NOW + 40 * DAY }), ['long-validity']);
  assert.deepEqual(codes({ nbf: NOW + 600, exp: NOW + 3600 }), ['not-yet-valid']);
  assert.deepEqual(codes({ iat: NOW + 3600, exp: NOW + 7200 }), ['iat-future']);
  const decoded = decodeToken(tokenFor({ exp: NOW - 3 * DAY }));
  const expired = analyzeToken(decoded, { now: NOW }).warnings.find((w) => w.code === 'expired');
  assert.equal(expired.title, 'Token expirado: expirou há 3 dias');
});

test('datas inválidas ou em milissegundos', () => {
  assert.deepEqual(codes({ exp: '2030-01-01' }), ['time-not-number']);
  assert.deepEqual(codes({ iat: NOW * 1000, exp: (NOW + 3600) * 1000 }), ['milliseconds', 'milliseconds']);
});

test('dados sensíveis no payload', () => {
  const found = findSensitiveData({
    email: 'maria@example.com',
    documento: '123.456.789-09',
    doc2: '52998224725',
    contato: { celular: '11987654321', fixo: '(11) 3456-7890' },
    internacional: '+5511987654321',
    senha: 'segredo123',
    client_secret: 'abc',
    lista: ['outra@example.com'],
    sub: '12345678901',
  });
  assert.deepEqual(found, [
    { path: 'email', kind: 'e-mail' },
    { path: 'documento', kind: 'CPF' },
    { path: 'doc2', kind: 'CPF' },
    { path: 'contato.celular', kind: 'telefone' },
    { path: 'contato.fixo', kind: 'telefone' },
    { path: 'internacional', kind: 'telefone' },
    { path: 'senha', kind: 'senha ou chave' },
    { path: 'client_secret', kind: 'senha ou chave' },
    { path: 'lista[0]', kind: 'e-mail' },
  ]);
  const w = analyzeToken(decodeToken(tokenFor({ exp: NOW + 60, password: 'x' })), { now: NOW }).warnings;
  assert.equal(w[0].code, 'sensitive');
  assert.match(w[0].detail, /não criptografado/);
});

test('validação de CPF', () => {
  assert.ok(isValidCpf('529.982.247-25'));
  assert.ok(isValidCpf('12345678909'));
  assert.ok(!isValidCpf('12345678900'));
  assert.ok(!isValidCpf('111.111.111-11'));
  assert.ok(!isValidCpf('1234'));
});

test('token grande, JWE, campos repetidos e chave no cabeçalho', () => {
  assert.ok(codes({ exp: NOW + 60, dados: 'x'.repeat(5000) }).includes('large'));
  const jwe = analyzeToken(decodeToken(`${textToBase64Url('{"alg":"dir","enc":"A256GCM"}')}..iv.cifra.tag`), { now: NOW });
  assert.deepEqual(jwe.warnings.map((x) => x.code), ['jwe']);
  assert.deepEqual(codes('{"exp":1760000060,"sub":"a","sub":"b"}'), ['duplicate']);
  assert.ok(codes({ exp: NOW + 60 }, { alg: 'RS256', jku: 'https://example.com/jwks.json' }).includes('key-in-header'));
});

test('claims explicadas, com datas', () => {
  const claims = describeClaims({ iss: 'https://login.example.com', exp: NOW + 7200, custom: 1, iat: 'ontem' }, NOW);
  assert.equal(claims[0].description, 'Emissor (issuer): quem emitiu o token.');
  assert.equal(claims[1].time.relative, 'expira em 2 h');
  assert.equal(claims[1].time.date.getTime(), (NOW + 7200) * 1000);
  assert.equal(claims[2].description, null);
  assert.equal(claims[3].time.date, null);
  assert.match(claims[3].time.relative, /valor inválido/);
});
