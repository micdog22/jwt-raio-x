import { decodeToken, JwtError } from './jwt.js';
import { analyzeToken } from './analysis.js';
import { verifySignature, signHs256, randomSecret, ALGORITHMS } from './signature.js';

const $ = (id) => document.getElementById(id);
const tokenInput = $('token');
const tokenStatus = $('token-status');
const warningsEl = $('warnings');
const decodedEl = $('decoded');
const headerJson = $('header-json');
const payloadJson = $('payload-json');
const headerFields = $('header-fields');
const claimsCard = $('claims-card');
const claimsEl = $('claims');
const signatureCard = $('signature-card');
const signatureEl = $('signature');
const verifyHint = $('verify-hint');
const keyLabel = $('key-label');
const keyInput = $('key');
const encodingField = $('encoding-field');
const encodingSelect = $('secret-encoding');
const verifyBtn = $('verify');
const verifyResult = $('verify-result');

const EXAMPLE_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const EXAMPLE_SECRET = 'your-256-bit-secret';

const dateFormat = new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'medium' });
let current = null;
let exampleKeyLoaded = false;

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child !== null && child !== undefined && child !== false) node.append(child);
  }
  return node;
}

function renderJson(target, formatted) {
  const nodes = formatted.tokens.map((t) => (t.type === 'space' ? document.createTextNode(t.value) : el('span', { class: `tok-${t.type}` }, t.value)));
  target.replaceChildren(...nodes);
}

function renderWarnings(warnings) {
  warningsEl.replaceChildren(...warnings.map((w) => el('div', { class: `alert ${w.level}` }, el('strong', {}, w.title), el('p', {}, w.detail))));
}

function valueText(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function renderFields(target, items) {
  target.replaceChildren(...items.map((item) => {
    const dd = el('dd', {}, el('span', { class: 'claim-value' }, valueText(item.value)));
    if (item.time) {
      const when = item.time.date ? `${dateFormat.format(item.time.date)} (horário local) · ` : '';
      dd.append(el('span', { class: 'claim-time' }, `${when}${item.time.relative}`));
    }
    if (item.description) dd.append(el('span', { class: 'claim-desc' }, item.description));
    return el('div', {}, el('dt', {}, item.name), dd);
  }));
}

function updateVerifyForm() {
  if (!current || current.type !== 'JWS') return;
  const alg = current.header.alg;
  const spec = ALGORITHMS[alg];
  const hmac = spec && spec.kind === 'hmac';
  encodingField.hidden = !hmac;
  keyLabel.textContent = hmac ? 'Segredo' : 'Chave pública (PEM ou JWK)';
  if (typeof alg === 'string' && alg.toLowerCase() === 'none') {
    verifyHint.textContent = 'Este token não tem assinatura, então não há o que verificar.';
  } else if (!spec) {
    verifyHint.textContent = `A verificação de «${alg}» não é suportada aqui. Suportados: ${Object.keys(ALGORITHMS).join(', ')}.`;
  } else if (hmac) {
    verifyHint.textContent = `${alg} usa um segredo compartilhado. Informe o segredo como texto ou em Base64.`;
  } else {
    verifyHint.textContent = `${alg} usa um par de chaves. Cole a chave pública em PEM (BEGIN PUBLIC KEY), uma JWK ou um JWKS.`;
  }
}

function clearDecoded() {
  current = null;
  decodedEl.hidden = true;
  warningsEl.replaceChildren();
  verifyResult.replaceChildren();
}

function inspect() {
  const raw = tokenInput.value;
  verifyResult.replaceChildren();
  if (!raw.trim()) {
    clearDecoded();
    tokenStatus.textContent = 'Cole um token JWT acima ou carregue o exemplo.';
    tokenStatus.className = 'status';
    return;
  }
  try {
    current = decodeToken(raw);
  } catch (err) {
    clearDecoded();
    tokenStatus.textContent = err instanceof JwtError ? err.message : 'Não foi possível ler este token.';
    tokenStatus.className = 'status error';
    return;
  }
  const analysis = analyzeToken(current);
  renderWarnings(analysis.warnings);
  decodedEl.hidden = false;
  renderJson(headerJson, current.headerFormatted);
  renderFields(headerFields, analysis.header.filter((h) => h.description));

  if (current.type === 'JWE') {
    tokenStatus.textContent = `Token JWE com 5 partes (${current.token.length} caracteres). Só o cabeçalho é legível.`;
    tokenStatus.className = 'status';
    payloadJson.textContent = '(conteúdo criptografado)';
    claimsCard.hidden = true;
    signatureCard.hidden = true;
    return;
  }
  tokenStatus.textContent = `Token com 3 partes (${current.token.length} caracteres), algoritmo ${valueText(current.header.alg ?? 'não informado')}.`;
  tokenStatus.className = 'status';
  renderJson(payloadJson, current.payloadFormatted);
  claimsCard.hidden = analysis.claims.length === 0;
  renderFields(claimsEl, analysis.claims);
  signatureCard.hidden = false;
  signatureEl.textContent = current.signature || '(vazia)';
  updateVerifyForm();
}

async function verify() {
  if (!current) return;
  verifyResult.replaceChildren();
  try {
    const result = await verifySignature(current, keyInput.value, { secretEncoding: encodingSelect.value });
    const box = result.valid
      ? el('div', { class: 'result valid' }, el('strong', {}, `✓ Assinatura válida (${result.alg})`),
        el('p', {}, 'O conteúdo não foi alterado e foi assinado com esta chave.'))
      : el('div', { class: 'result invalid' }, el('strong', {}, `✗ Assinatura inválida (${result.alg})`),
        el('p', {}, 'O token foi alterado ou a chave informada não é a que assinou o token.'));
    for (const note of result.notes) box.append(el('p', { class: 'small' }, note));
    verifyResult.append(box);
  } catch (err) {
    const message = err instanceof JwtError ? err.message : 'Não foi possível verificar com esta chave.';
    verifyResult.append(el('div', { class: 'result error' }, el('strong', {}, 'Não deu para verificar'), el('p', {}, message)));
  }
}

function loadExample() {
  tokenInput.value = EXAMPLE_TOKEN;
  keyInput.value = EXAMPLE_SECRET;
  encodingSelect.value = 'text';
  exampleKeyLoaded = true;
  inspect();
}

let inputTimer = null;
tokenInput.addEventListener('input', () => {
  if (exampleKeyLoaded) {
    keyInput.value = '';
    exampleKeyLoaded = false;
  }
  clearTimeout(inputTimer);
  inputTimer = setTimeout(inspect, 120);
});
keyInput.addEventListener('input', () => {
  exampleKeyLoaded = false;
  verifyResult.replaceChildren();
});
encodingSelect.addEventListener('change', () => verifyResult.replaceChildren());
verifyBtn.addEventListener('click', verify);
$('load-example').addEventListener('click', loadExample);
$('clear-token').addEventListener('click', () => {
  tokenInput.value = '';
  keyInput.value = '';
  exampleKeyLoaded = false;
  inspect();
  tokenInput.focus();
});

// Abas ------------------------------------------------------------------------
const tabs = [$('tab-inspect'), $('tab-generate')];
function selectTab(tab, focus = false) {
  for (const t of tabs) {
    const selected = t === tab;
    t.setAttribute('aria-selected', String(selected));
    t.tabIndex = selected ? 0 : -1;
    $(t.getAttribute('aria-controls')).hidden = !selected;
  }
  if (focus) tab.focus();
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', (e) => {
    const moves = { ArrowRight: 1, ArrowLeft: -1 };
    if (e.key in moves) {
      e.preventDefault();
      selectTab(tabs[(index + moves[e.key] + tabs.length) % tabs.length], true);
    } else if (e.key === 'Home' || e.key === 'End') {
      e.preventDefault();
      selectTab(e.key === 'Home' ? tabs[0] : tabs[tabs.length - 1], true);
    }
  });
});

// Gerador ---------------------------------------------------------------------
const genHeader = $('gen-header');
const genPayload = $('gen-payload');
const genSecret = $('gen-secret');
const genStatus = $('gen-status');
const genOutput = $('gen-output');

function defaultPayload() {
  const now = Math.floor(Date.now() / 1000);
  return JSON.stringify({ sub: '1234567890', name: 'Maria Exemplo', role: 'leitor', iat: now, exp: now + 3600 }, null, 2);
}

async function generate() {
  genStatus.replaceChildren();
  genStatus.className = 'status';
  try {
    const { token, notes } = await signHs256(genHeader.value, genPayload.value, genSecret.value);
    genOutput.value = token;
    genStatus.className = 'status ok';
    genStatus.append(el('span', {}, 'Token gerado.'));
    for (const note of notes) genStatus.append(el('p', { class: 'muted small' }, note));
  } catch (err) {
    genOutput.value = '';
    genStatus.className = 'status error';
    genStatus.textContent = err instanceof JwtError ? err.message : 'Não foi possível gerar o token.';
  }
}

$('generate').addEventListener('click', generate);
$('gen-random').addEventListener('click', () => {
  genSecret.value = randomSecret();
});
$('gen-copy').addEventListener('click', async (e) => {
  if (!genOutput.value) return;
  const button = e.currentTarget;
  try {
    await navigator.clipboard.writeText(genOutput.value);
    button.textContent = 'Copiado!';
  } catch {
    genOutput.select();
    button.textContent = 'Selecionado';
  }
  setTimeout(() => {
    button.textContent = 'Copiar token';
  }, 1500);
});
$('gen-inspect').addEventListener('click', async () => {
  if (!genOutput.value) return;
  tokenInput.value = genOutput.value;
  keyInput.value = genSecret.value;
  encodingSelect.value = 'text';
  exampleKeyLoaded = false;
  selectTab(tabs[0]);
  inspect();
  await verify();
  tokenInput.focus();
});

genHeader.value = JSON.stringify({ alg: 'HS256', typ: 'JWT' }, null, 2);
genPayload.value = defaultPayload();
genSecret.value = randomSecret();
loadExample();
