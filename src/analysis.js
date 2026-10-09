// Explicação das claims e alertas sobre o conteúdo do token. "now" é injetável (segundos desde 1970).

export const PAYLOAD_CLAIMS = {
  iss: 'Emissor (issuer): quem emitiu o token.',
  sub: 'Assunto (subject): a quem o token se refere, normalmente o ID do usuário.',
  aud: 'Audiência (audience): para quem o token foi feito, como a API ou o aplicativo que deve aceitá-lo.',
  exp: 'Expiração: a partir deste momento o token não deve mais ser aceito.',
  nbf: 'Não antes de (not before): o token só vale a partir deste momento.',
  iat: 'Emitido em (issued at): quando o token foi criado.',
  jti: 'ID do token (JWT ID): identificador único, útil para impedir que o mesmo token seja reutilizado.',
  azp: 'Parte autorizada (authorized party): o client_id do aplicativo para o qual o token foi emitido.',
  scope: 'Escopos (OAuth 2.0): permissões concedidas, separadas por espaço.',
  scp: 'Escopos, na variação usada por alguns provedores (texto ou lista).',
  roles: 'Papéis do usuário (perfis de acesso). Não é padronizado: cada sistema define os seus.',
  groups: 'Grupos do usuário. Não é padronizado: cada sistema define os seus.',
  email: 'E-mail do usuário.',
  email_verified: 'Se o provedor confirmou o e-mail.',
  name: 'Nome completo do usuário.',
  given_name: 'Prenome.',
  family_name: 'Sobrenome.',
  preferred_username: 'Nome de usuário preferido.',
  nickname: 'Apelido.',
  picture: 'Endereço da foto de perfil.',
  locale: 'Idioma e região do usuário (ex.: pt-BR).',
  zoneinfo: 'Fuso horário do usuário (ex.: America/Sao_Paulo).',
  phone_number: 'Telefone do usuário.',
  phone_number_verified: 'Se o provedor confirmou o telefone.',
  birthdate: 'Data de nascimento.',
  address: 'Endereço postal.',
  updated_at: 'Quando os dados do perfil foram atualizados pela última vez.',
  auth_time: 'Quando o usuário fez login (autenticação).',
  nonce: 'Valor aleatório que liga o token ao pedido de login, para evitar reaproveitamento.',
  acr: 'Nível de garantia da autenticação (authentication context class).',
  amr: 'Métodos usados na autenticação (ex.: senha, código).',
  sid: 'ID da sessão de login.',
  client_id: 'ID do aplicativo (cliente OAuth) que pediu o token.',
  at_hash: 'Hash do access token emitido junto (OpenID Connect).',
  c_hash: 'Hash do código de autorização (OpenID Connect).',
  cnf: 'Confirmação: chave à qual o token está vinculado.',
  act: 'Ator: quem está agindo em nome do usuário (delegação).',
};

export const HEADER_FIELDS = {
  alg: 'Algoritmo da assinatura (ex.: HS256, RS256, ES256).',
  typ: 'Tipo do token, normalmente «JWT».',
  cty: 'Tipo do conteúdo; «JWT» indica um token dentro de outro.',
  kid: 'ID da chave usada na assinatura; ajuda o servidor a escolher a chave certa.',
  jku: 'URL de um conjunto de chaves públicas (JWKS).',
  jwk: 'Chave pública embutida no próprio token.',
  x5u: 'URL de um certificado X.509.',
  x5c: 'Cadeia de certificados X.509.',
  x5t: 'Impressão digital (SHA-1) do certificado.',
  'x5t#S256': 'Impressão digital (SHA-256) do certificado.',
  crit: 'Extensões que o receptor é obrigado a entender.',
  enc: 'Algoritmo de criptografia do conteúdo (JWE).',
  zip: 'Compressão aplicada antes da criptografia (JWE).',
};

export const TIME_CLAIMS = ['exp', 'nbf', 'iat', 'auth_time', 'updated_at'];
const DAY = 86400;
const LONG_VALIDITY_DAYS = 30;
const LARGE_TOKEN = 4096;

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

// Duração aproximada, sempre arredondada para baixo: "45 s", "12 min", "2 h", "3 dias", "4 meses", "2 anos".
export function formatSpan(seconds) {
  const s = Math.abs(seconds);
  if (s < 60) return `${Math.floor(s)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < DAY) return `${Math.floor(s / 3600)} h`;
  const days = Math.floor(s / DAY);
  if (days < 30) return plural(days, 'dia', 'dias');
  if (days < 365) return plural(Math.floor(days / 30), 'mês', 'meses');
  return plural(Math.floor(days / 365), 'ano', 'anos');
}

// Frase relativa para cada claim de data: "expira em 2 h", "expirou há 3 dias"...
export function describeTime(claim, value, now) {
  const diff = value - now;
  const span = formatSpan(diff);
  const future = diff > 0;
  if (Math.abs(diff) < 1) {
    return { exp: 'expira agora', nbf: 'passa a valer agora', iat: 'emitido agora' }[claim] || 'agora';
  }
  switch (claim) {
    case 'exp':
      return future ? `expira em ${span}` : `expirou há ${span}`;
    case 'nbf':
      return future ? `passa a valer em ${span}` : `vale desde ${span} atrás`;
    case 'iat':
      return future ? `emitido no futuro (daqui a ${span})` : `emitido há ${span}`;
    case 'auth_time':
      return future ? `no futuro (daqui a ${span})` : `login há ${span}`;
    default:
      return future ? `daqui a ${span}` : `há ${span}`;
  }
}

function isNumericDate(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

// Lista as claims do payload com explicação e, para datas, o instante e a frase relativa.
export function describeClaims(payload, now) {
  return Object.entries(payload).map(([name, value]) => {
    const item = { name, value, description: PAYLOAD_CLAIMS[name] || null, time: null };
    if (TIME_CLAIMS.includes(name)) {
      if (isNumericDate(value)) {
        const ms = value * 1000;
        const valid = Math.abs(ms) <= 8.64e15;
        item.time = { date: valid ? new Date(ms) : null, relative: valid ? describeTime(name, value, now) : 'data fora do intervalo válido' };
      } else {
        item.time = { date: null, relative: 'valor inválido: deveria ser um número de segundos desde 01/01/1970 (UTC)' };
      }
    }
    return item;
  });
}

export function describeHeader(header) {
  return Object.entries(header).map(([name, value]) => ({ name, value, description: HEADER_FIELDS[name] || null }));
}

// Dados com cara de sensíveis ------------------------------------------------

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const CPF_FORMATTED = /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/;
const PHONE = [
  /\(\d{2}\)\s?9?\d{4}[-\s]?\d{4}\b/, // (11) 98765-4321
  /\+55\s?\(?\d{2}\)?\s?9?\d{4}[-\s]?\d{4}\b/, // +55 11 98765-4321
  /^\+\d{10,15}$/, // E.164: +5511987654321
];
const PHONE_KEYS = /^(phone|phone_number|telefone|celular|tel|fone|mobile|whatsapp)$/i;
const CPF_KEYS = /^(cpf|nr_cpf|num_cpf|numero_cpf)$/i;
const SECRET_KEY_PARTS = [
  'password', 'passwd', 'senha', 'secret', 'segredo', 'apikey', 'api_key', 'api-key', 'private_key', 'privatekey',
  'access_token', 'refresh_token', 'cvv', 'card_number', 'cartao', 'cartão',
];

export function isValidCpf(text) {
  const digits = String(text).replace(/\D/g, '');
  if (digits.length !== 11 || /^(\d)\1{10}$/.test(digits)) return false;
  const check = (len) => {
    let sum = 0;
    for (let i = 0; i < len; i++) sum += Number(digits[i]) * (len + 1 - i);
    const rest = (sum * 10) % 11;
    return rest === 10 ? 0 : rest;
  };
  return check(9) === Number(digits[9]) && check(10) === Number(digits[10]);
}

function isSecretKey(key) {
  const k = key.toLowerCase();
  return k === 'pwd' || k === 'pass' || SECRET_KEY_PARTS.some((part) => k.includes(part));
}

// Percorre o payload e devolve [{ path, kind }] com kind = 'e-mail' | 'CPF' | 'telefone' | 'senha ou chave'.
export function findSensitiveData(value, path = '') {
  const found = [];
  const visit = (node, nodePath, key) => {
    if (key !== null) {
      if (isSecretKey(key)) found.push({ path: nodePath, kind: 'senha ou chave' });
      else if (CPF_KEYS.test(key)) found.push({ path: nodePath, kind: 'CPF' });
      else if (PHONE_KEYS.test(key)) found.push({ path: nodePath, kind: 'telefone' });
    }
    if (typeof node === 'string') {
      const already = found.some((f) => f.path === nodePath);
      if (already) return;
      if (EMAIL.test(node)) found.push({ path: nodePath, kind: 'e-mail' });
      else if (CPF_FORMATTED.test(node) || (/^\d{11}$/.test(node) && isValidCpf(node))) found.push({ path: nodePath, kind: 'CPF' });
      else if (PHONE.some((re) => re.test(node))) found.push({ path: nodePath, kind: 'telefone' });
    } else if (Array.isArray(node)) {
      node.forEach((item, i) => visit(item, `${nodePath}[${i}]`, null));
    } else if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) visit(v, nodePath ? `${nodePath}.${k}` : k, k);
    }
  };
  visit(value, path, null);
  return found;
}

// Alertas ---------------------------------------------------------------------

function warning(code, level, title, detail) {
  return { code, level, title, detail };
}

export function analyzeToken(decoded, { now = Date.now() / 1000 } = {}) {
  const warnings = [];
  const size = decoded.token.length;

  if (decoded.type === 'JWE') {
    warnings.push(warning('jwe', 'info', 'Token criptografado (JWE)',
      'Este token tem 5 partes: é um JWE. O conteúdo está cifrado e só pode ser lido por quem tem a chave do destinatário. Apenas o cabeçalho é legível.'));
    if (size > LARGE_TOKEN) warnings.push(largeWarning(size));
    return { warnings, header: describeHeader(decoded.header), claims: [] };
  }

  const { header, payload } = decoded;
  const alg = typeof header.alg === 'string' ? header.alg : null;
  if (!alg) {
    warnings.push(warning('no-alg', 'danger', 'Cabeçalho sem «alg»', 'Sem o algoritmo, não há como verificar a assinatura. Um servidor deve recusar este token.'));
  } else if (alg.toLowerCase() === 'none') {
    warnings.push(warning('alg-none', 'danger', 'Token sem assinatura (alg: none)',
      'Qualquer pessoa pode alterar o conteúdo deste token. Servidores nunca devem aceitar tokens com alg «none».'));
  }
  if (['jku', 'x5u', 'jwk'].some((k) => k in header)) {
    warnings.push(warning('key-in-header', 'info', 'O cabeçalho aponta para a chave de verificação',
      'Campos como jku, x5u e jwk dizem onde buscar a chave (ou trazem a própria chave). O servidor só deve usar chaves que ele já conhece e confia.'));
  }
  const duplicates = [...decoded.headerFormatted.duplicates, ...(decoded.payloadFormatted ? decoded.payloadFormatted.duplicates : [])];
  if (duplicates.length) {
    warnings.push(warning('duplicate', 'warn', 'Campos repetidos no JSON',
      `Aparecem mais de uma vez: ${[...new Set(duplicates)].join(', ')}. Cada biblioteca pode ler um valor diferente; o padrão recomenda recusar ou usar só o último.`));
  }

  if (!decoded.payloadIsJson) {
    warnings.push(warning('payload-not-json', 'info', 'O payload não é um objeto JSON',
      'Isso é possível em um JWS genérico, mas um JWT precisa ter um objeto JSON com as claims.'));
    if (size > LARGE_TOKEN) warnings.push(largeWarning(size));
    return { warnings, header: describeHeader(header), claims: [] };
  }

  const { exp, nbf, iat } = payload;
  for (const name of TIME_CLAIMS) {
    const value = payload[name];
    if (value === undefined) continue;
    if (!isNumericDate(value)) {
      warnings.push(warning('time-not-number', 'warn', `«${name}» não é um número`,
        `As datas do JWT devem ser números de segundos desde 01/01/1970 (UTC). Valor encontrado: ${JSON.stringify(value)}.`));
    } else if (Math.abs(value) > 1e11) {
      warnings.push(warning('milliseconds', 'warn', `«${name}» parece estar em milissegundos`,
        'O padrão usa segundos. Com milissegundos, a data cai milhares de anos no futuro e a expiração na prática não funciona.'));
    }
  }

  if (exp === undefined) {
    warnings.push(warning('no-exp', 'warn', 'Sem data de expiração (exp)',
      'Se o servidor não impuser outro limite, este token vale para sempre.'));
  } else if (isNumericDate(exp)) {
    if (now >= exp) {
      warnings.push(warning('expired', 'warn', `Token expirado: ${describeTime('exp', exp, now)}`, 'Um servidor deve recusar este token.'));
    }
    const start = isNumericDate(iat) ? iat : isNumericDate(nbf) ? nbf : null;
    const validity = start !== null ? exp - start : exp - now;
    if (validity > LONG_VALIDITY_DAYS * DAY && Math.abs(exp) <= 1e11) {
      const days = Math.floor(validity / DAY);
      warnings.push(warning('long-validity', 'warn', `Validade longa: ${plural(days, 'dia', 'dias')}`,
        start !== null
          ? `Entre ${isNumericDate(iat) ? 'a emissão (iat)' : 'o início (nbf)'} e a expiração (exp) há mais de ${LONG_VALIDITY_DAYS} dias. Se o token vazar, ele continua útil por muito tempo.`
          : `O token ainda vale por mais de ${LONG_VALIDITY_DAYS} dias. Se ele vazar, continua útil por muito tempo.`));
    }
  }
  if (isNumericDate(nbf) && nbf > now) {
    warnings.push(warning('not-yet-valid', 'warn', `Ainda não é válido: ${describeTime('nbf', nbf, now)}`,
      'Antes do momento indicado em nbf, o servidor deve recusar o token.'));
  }
  if (isNumericDate(iat) && iat > now + 60 && Math.abs(iat) <= 1e11) {
    warnings.push(warning('iat-future', 'warn', 'Data de emissão no futuro (iat)',
      'Pode indicar relógio errado no servidor que emitiu o token.'));
  }

  const sensitive = findSensitiveData(payload);
  if (sensitive.length) {
    const list = sensitive.map((s) => `${s.kind} em «${s.path}»`).join('; ');
    warnings.push(warning('sensitive', 'warn', 'Dados que parecem pessoais ou secretos no payload',
      `Encontrado: ${list}. Lembre que o payload é só codificado em Base64URL, não criptografado: qualquer pessoa com o token consegue ler esses dados.`));
  }
  if (size > LARGE_TOKEN) warnings.push(largeWarning(size));

  return { warnings, header: describeHeader(header), claims: describeClaims(payload, now) };
}

function largeWarning(size) {
  return warning('large', 'warn', `Token grande (${(size / 1024).toFixed(1).replace('.', ',')} KB)`,
    'Tokens grandes deixam cada requisição mais pesada e podem estourar limites de tamanho de cookies (cerca de 4 KB) e de cabeçalhos HTTP em alguns servidores.');
}
