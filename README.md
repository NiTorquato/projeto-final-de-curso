# Serviço de reputação para identidades digitais (PFC)

Protótipo que, ao receber uma mensagem `m` de um remetente declarado, gera um **link de verificação
único** e, ao ser acessado, calcula um **nível de confiança (0–100)** para a identidade e para a mensagem.

## Como executar

```bash
pip install -r requirements.txt
python main.py            # http://127.0.0.1:5000
python -m unittest -v     # testes
```

Login de demonstração: `Banco/autenticacao.json` (`nome` e `Chave_de_acesso`).
Variáveis opcionais: `PFC_SECRET_KEY`, `PFC_CHAVE_SISTEMA`, `PFC_HOST`, `FLASK_DEBUG=1`,
`PFC_WEBAUTHN_RP_ID` e `PFC_WEBAUTHN_ORIGIN`.

## Estrutura

| Arquivo | Papel |
|---|---|
| `main.py` | Serviço Flask: login, geração/validação do link, decisão |
| `reputacao.py` | Máquina de cálculo de reputação (modelo) |
| `Banco/autenticacao.json` | Credenciais do verificador |
| `Banco/passkeys.json` | Credenciais públicas das passkeys cadastradas |
| `Banco/interacoes.json` | BD de interações: identidade `i`, chave `ch`, histórico, peers, autoridade, domínios |
| `templates/` | Telas: login, painel, gerar link, resultado |
| `test_app.py` | Testes automatizados |

## Autenticação por link aleatório (páginas 1 e 2)

1. **Página 1** (`/`): a cada carregamento gera um link novo e aleatório (`/auth/<token>`, 256 bits) e fica
   consultando `/status/<token>` a cada 2 s.
2. **Página 2** (`/auth/<token>`): aberta pelo link, pede confirmação com uma passkey cadastrada
   (por exemplo, Windows Hello).
3. Se a assinatura WebAuthn for válida, o link passa a `autenticado` e a **página 1 mostra
   "Autenticação concluída"**.

Regras do link: expira em 30 s, uso único e é bloqueado após 1 tentativa inválidas.
A página 1 apenas é *informada*; ela não recebe sessão de acesso. Se no futuro ela passar a receber sessão,
é preciso confirmar na página 2 qual dispositivo está sendo autorizado (risco de sequestro, ver limitações).

O login do painel é feito preferencialmente com passkey em `/entrar`. No primeiro acesso, entre
uma vez com o nome e a chave atual pela opção de configuração e cadastre a passkey no painel.
A página de autenticação por link também usa essa passkey; ela não aceita nome ou senha. A chave
privada nunca é enviada ao servidor: o arquivo `Banco/passkeys.json` guarda somente
o identificador e a chave pública do autenticador. Depois do cadastro, o login por chave digitada é
desativado; cadastre passkeys em mais de um dispositivo para ter uma alternativa caso perca acesso
a um deles. Para recuperação administrativa neste protótipo, remova as credenciais do arquivo
`Banco/passkeys.json` e reinicie o servidor; então o cadastro inicial com a chave volta a ser permitido.

O cadastro exige verificação do usuário no autenticador e cria uma credencial residente, permitindo
o uso de passkeys sem senha. Em desenvolvimento, `localhost` funciona como contexto seguro; em
produção, configure `PFC_WEBAUTHN_RP_ID` com o domínio da aplicação e `PFC_WEBAUTHN_ORIGIN` com a
origem HTTPS exata (por exemplo, `https://login.exemplo.com`). Passkeys são vinculadas ao domínio e
à origem, portanto essa configuração precisa corresponder ao endereço usado pelo navegador.

## Fluxo de verificação de reputação

1. O verificador faz login e abre **Verificar mensagem recebida**.
2. Informa o remetente declarado e o texto de `m`.
3. O sistema busca `i` e `ch` no BD, cria `nonce` aleatório, assina `nonce|ts|i|ch` (HMAC-SHA256), guarda
   o desafio no servidor (com `ts` e `m`) e **exibe o link** `/verify?id=…&nonce=…&sig=…` na tela.
4. Ao acessar o link (login exigido), o sistema:
   1. localiza o desafio e `ch` no BD;
   2. valida assinatura, expiração (300 s) e uso único (anti-replay);
   3. extrai o contexto de `m` (URLs);
   4. calcula a reputação;
   5. decide: nível `< 50` → **alerta**; caso contrário → **confirmação**, com explicação dos motivos.

Também responde em JSON: `/verify?...&formato=json` ou `Accept: application/json`.

## Modelo de reputação (`reputacao.py`)

`nível = round(base × fator_contexto)`

- **base**: média ponderada das fontes disponíveis — direta (50%), web of trust (25%), hierárquica (25%);
  pesos renormalizados se faltar alguma fonte. Sem nenhuma evidência: base = 25.
- **fator_contexto** (0–1): penaliza URLs sem HTTPS, IP literal, encurtador, punycode e domínio não associado à identidade.
- Faixas: **alto** ≥ 80, **médio** 50–79, **baixo** < 50.

## Limitações conhecidas (declarar no texto do PFC)

- Link aleatório: quem induz a vítima a abrir e autenticar o link do atacante faz a página do atacante ser
  notificada (ataque tipo "QRLjacking"). Hoje o impacto é só a notificação; com sessão seria grave.
- O link trafega em HTTP no protótipo; em produção, HTTPS é obrigatório.

- Pesos, penalidades e faixas são escolhas do protótipo, não validadas.
- Web of trust e autoridade hierárquica são **dados estáticos** no JSON; não há consulta real à rede/OAuth.
- O fluxo avalia a reputação da identidade *alegada*; não há prova de posse da chave de `i`
  (desafio assinado por `i`). Uma mensagem forjada sem sinais no contexto herda a reputação de `i`.
- Desafios em memória (perdem-se ao reiniciar); segredos com valor padrão no código; senha em texto no JSON.
