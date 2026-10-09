# JWT Raio-X — inspecione tokens JWT sem enviá-los para nenhum servidor (HTML + JavaScript)

Quem trabalha com APIs vive colando tokens JWT em sites para ver o que tem dentro. O problema é que um token válido é uma credencial: mandá-lo para um servidor de terceiros é um risco. O JWT Raio-X decodifica, explica e verifica o token inteiramente no navegador.

Além de mostrar o cabeçalho e o payload formatados, ele explica cada claim em português, converte as datas para o seu horário local e aponta problemas comuns, como `alg: none`, falta de expiração e dados pessoais no payload.

**Acesse online:** https://micdog22.github.io/jwt-raio-x/

## Recursos

- Cabeçalho e payload decodificados (Base64URL + UTF-8), com JSON formatado e destaque de sintaxe. Os números aparecem exatamente como estão no token.
- Claims padrão explicadas em português: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `azp`, `scope`/`scp`, `roles`, `email`, `name` e outras do OpenID Connect.
- Datas convertidas para o horário local, com tempo relativo ("expira em 2 h", "expirou há 3 dias").
- Alertas:
  - `alg: none` (token sem assinatura);
  - sem `exp`, validade maior que 30 dias, token expirado ou ainda não válido (`nbf`);
  - dados com cara de sensíveis no payload (e-mail, CPF, telefone, campos como `senha` ou `password`), lembrando que o payload só é codificado, não criptografado;
  - datas em milissegundos, campos repetidos no JSON, token muito grande;
  - JWE (5 partes): explica que o conteúdo é criptografado e mostra só o cabeçalho.
- Verificação da assinatura com Web Crypto:
  - HS256, HS384 e HS512 com segredo em texto ou Base64;
  - RS256, RS384, RS512, PS256, PS384 e PS512 com chave pública em PEM (SPKI) ou JWK;
  - ES256 e ES384 (assinatura no formato r||s, como no JWS).
  - Aceita também um JWKS e escolhe a chave pelo `kid`.
- Aba **Gerar token de teste**: cria um token HS256 a partir do JSON do cabeçalho e do payload, com botão para gerar um segredo aleatório.

## Como usar

1. Cole o token na caixa (pode ser com `Bearer ` na frente).
2. Leia os alertas, o cabeçalho, o payload e a lista de claims explicadas.
3. Para verificar a assinatura, informe o segredo (HS*) ou a chave pública (RS*, PS*, ES*) e clique em **Verificar**.

O botão **Carregar exemplo** usa o token clássico de demonstração, que é válido com o segredo `your-256-bit-secret`.

## Como rodar localmente

Módulos ES não carregam via `file://`, então sirva a pasta com qualquer servidor estático:

```bash
python3 -m http.server 8000
```

Depois abra http://localhost:8000. A Web Crypto exige contexto seguro: funciona em `localhost` e em HTTPS.

## Testes

```bash
npm test
```

Os testes (com `node:test`, sem dependências) cobrem a decodificação do token clássico e a verificação com `your-256-bit-secret`, payloads UTF-8 com acentos, tokens malformados, todos os alertas com um "agora" fixo, HS256 assinar e verificar, e RS256, PS256, ES256 e ES384 com chaves geradas na hora com `crypto.subtle.generateKey`.

## Como funciona

- O token é dividido nas partes separadas por ponto. Cada parte é decodificada de Base64URL e lida como UTF-8.
- O JSON é validado e reformatado por um analisador próprio, que preserva o texto original de cada valor e detecta chaves repetidas.
- A verificação usa a API Web Crypto do navegador (`crypto.subtle.verify`) sobre os bytes de `cabeçalho.payload`.
- Nada é enviado pela rede e nada é salvo no navegador.

Lembre: decodificar não é validar. Quem recebe o token (o servidor) precisa verificar a assinatura com a chave certa e checar `exp`, `nbf`, `iss` e `aud`.

## Contribuindo

Issues e pull requests são bem-vindos.

## Licença

MIT — veja [LICENSE](LICENSE).
