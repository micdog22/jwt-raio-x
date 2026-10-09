// Decodificação de JWT (JWS e JWE): Base64URL, UTF-8 e JSON formatado com destaque de sintaxe.

export class JwtError extends Error {}

const utf8 = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();

export function base64UrlToBytes(text) {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(text)) throw new JwtError('contém caracteres que não pertencem ao Base64URL');
  let s = text.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/');
  if (s.length % 4 === 1) throw new JwtError('tem um tamanho impossível para Base64URL');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function textToBase64Url(text) {
  return bytesToBase64Url(encoder.encode(text));
}

// Aceita "Bearer ...", "Authorization: Bearer ...", aspas em volta e quebras de linha no meio.
export function cleanTokenInput(input) {
  return String(input ?? '')
    .trim()
    .replace(/^(?:authorization\s*:\s*)?bearer\s+/i, '')
    .replace(/^["'`]+|["'`]+$/g, '')
    .replace(/\s+/g, '');
}

function decodeSegment(segment, label) {
  let bytes;
  try {
    bytes = base64UrlToBytes(segment);
  } catch (err) {
    throw new JwtError(`${label} ${err.message}.`);
  }
  try {
    return utf8.decode(bytes);
  } catch {
    throw new JwtError(`${label} não é texto UTF-8 válido.`);
  }
}

function parseJsonObject(text, label) {
  const formatted = formatJson(text, label);
  const value = JSON.parse(text);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new JwtError(`${label} precisa ser um objeto JSON ({ ... }).`);
  }
  return { value, formatted };
}

// Decodifica sem verificar nada. Lança JwtError com mensagem em português se o token estiver malformado.
export function decodeToken(input) {
  const token = cleanTokenInput(input);
  if (!token) throw new JwtError('Cole um token JWT para começar.');
  const parts = token.split('.');

  if (parts.length === 5) {
    const headerText = decodeSegment(parts[0], 'O cabeçalho');
    const header = parseJsonObject(headerText, 'O cabeçalho');
    return { type: 'JWE', token, parts, header: header.value, headerText, headerFormatted: header.formatted };
  }
  if (parts.length !== 3) {
    throw new JwtError(`Um JWT tem 3 partes separadas por ponto (ou 5, se for criptografado). Este tem ${parts.length}.`);
  }
  if (!parts[0]) throw new JwtError('O cabeçalho está vazio.');

  const headerText = decodeSegment(parts[0], 'O cabeçalho');
  const header = parseJsonObject(headerText, 'O cabeçalho');
  const payloadText = decodeSegment(parts[1], 'O payload');

  let payload = null;
  let payloadFormatted = null;
  let payloadIsJson = false;
  try {
    const parsed = parseJsonObject(payloadText, 'O payload');
    payload = parsed.value;
    payloadFormatted = parsed.formatted;
    payloadIsJson = true;
  } catch (err) {
    if (!(err instanceof JwtError)) throw err;
    payloadFormatted = { tokens: [{ type: 'string', value: payloadText }], duplicates: [], error: err.message };
  }

  let signatureBytes = null;
  if (parts[2]) {
    try {
      signatureBytes = base64UrlToBytes(parts[2]);
    } catch (err) {
      throw new JwtError(`A assinatura ${err.message}.`);
    }
  }

  return {
    type: 'JWS',
    token,
    parts,
    header: header.value,
    headerText,
    headerFormatted: header.formatted,
    payload,
    payloadText,
    payloadIsJson,
    payloadFormatted,
    signature: parts[2],
    signatureBytes,
    signingInput: `${parts[0]}.${parts[1]}`,
  };
}

// Valida e reformata JSON (indentação de 2 espaços) preservando o texto original de cada valor.
// Retorna tokens { type: 'punct' | 'key' | 'string' | 'number' | 'literal' | 'space', value } e chaves duplicadas.
export function formatJson(text, label = 'O JSON') {
  let i = 0;
  const tokens = [];
  const duplicates = [];
  const emit = (type, value) => tokens.push({ type, value });
  const newline = (depth) => emit('space', `\n${'  '.repeat(depth)}`);
  const fail = (message) => {
    throw new JwtError(`${label} não é JSON válido: ${message} (posição ${Math.min(i, text.length) + 1}).`);
  };
  const skipSpace = () => {
    while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++;
  };
  const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

  function readString() {
    const start = i;
    i++;
    while (i < text.length) {
      const c = text[i];
      if (c === '"') {
        i++;
        return text.slice(start, i);
      }
      if (c === '\\') {
        const next = text[i + 1];
        if (next === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) fail('escape \\u inválido');
          i += 6;
          continue;
        }
        if (next === undefined || !'"\\/bfnrt'.includes(next)) fail('escape inválido');
        i += 2;
        continue;
      }
      if (c < ' ') fail('caractere de controle dentro de um texto');
      i++;
    }
    return fail('texto sem aspas de fechamento');
  }

  function readValue(depth, path) {
    skipSpace();
    const c = text[i];
    if (c === '{') return readObject(depth, path);
    if (c === '[') return readArray(depth, path);
    if (c === '"') return emit('string', readString());
    NUMBER.lastIndex = i;
    const number = NUMBER.exec(text);
    if (number && number[0]) {
      i += number[0].length;
      return emit('number', number[0]);
    }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, i)) {
        i += literal.length;
        return emit('literal', literal);
      }
    }
    return fail(c === undefined ? 'terminou antes do esperado' : `valor inesperado «${c}»`);
  }

  function readObject(depth, path) {
    emit('punct', '{');
    i++;
    skipSpace();
    if (text[i] === '}') {
      i++;
      return emit('punct', '}');
    }
    const seen = new Set();
    for (;;) {
      skipSpace();
      if (text[i] !== '"') fail('esperava o nome de um campo entre aspas');
      newline(depth + 1);
      const rawKey = readString();
      const key = JSON.parse(rawKey);
      const keyPath = path ? `${path}.${key}` : key;
      if (seen.has(key)) duplicates.push(keyPath);
      seen.add(key);
      emit('key', rawKey);
      skipSpace();
      if (text[i] !== ':') fail('esperava «:»');
      i++;
      emit('punct', ': ');
      readValue(depth + 1, keyPath);
      skipSpace();
      if (text[i] === ',') {
        i++;
        emit('punct', ',');
        continue;
      }
      if (text[i] === '}') {
        i++;
        newline(depth);
        return emit('punct', '}');
      }
      fail('esperava «,» ou «}»');
    }
  }

  function readArray(depth, path) {
    emit('punct', '[');
    i++;
    skipSpace();
    if (text[i] === ']') {
      i++;
      return emit('punct', ']');
    }
    for (let index = 0; ; index++) {
      newline(depth + 1);
      readValue(depth + 1, `${path}[${index}]`);
      skipSpace();
      if (text[i] === ',') {
        i++;
        emit('punct', ',');
        continue;
      }
      if (text[i] === ']') {
        i++;
        newline(depth);
        return emit('punct', ']');
      }
      fail('esperava «,» ou «]»');
    }
  }

  try {
    readValue(0, '');
    skipSpace();
    if (i < text.length) fail('há conteúdo depois do fim do JSON');
  } catch (err) {
    if (err instanceof RangeError) throw new JwtError(`${label} tem níveis demais de aninhamento.`);
    throw err;
  }
  return { tokens, duplicates };
}

export function tokensToText(tokens) {
  return tokens.map((t) => t.value).join('');
}
