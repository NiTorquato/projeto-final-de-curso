import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

import reputacao
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

app = Flask(__name__)
app.secret_key = os.environ.get("PFC_SECRET_KEY", "chave-secreta-do-projeto")

BASE_DIR = Path(__file__).resolve().parent
BANCO_DIR = BASE_DIR / "Banco"
BANCO_DIR.mkdir(exist_ok=True)
ARQUIVO_USUARIOS = BANCO_DIR / "autenticacao.json"
ARQUIVO_INTERACOES = BANCO_DIR / "interacoes.json"
ARQUIVO_PASSKEYS = BANCO_DIR / "passkeys.json"

CHAVE_PRIVADA_SISTEMA = os.environ.get("PFC_CHAVE_SISTEMA", "chave_secreta_do_middleware_pfc").encode("utf-8")
LIMIAR_TEMPO_VALIDADE_SEGUNDOS = 30
LIMIAR_DE_CONFIANCA = reputacao.LIMIAR_DE_CONFIANCA
VALIDADE_DESAFIO_WEBAUTHN_SEGUNDOS = 300

# Desafios emitidos (nonce -> registro). Em memória: somem ao reiniciar o servidor.
DESAFIOS = {}
TRAVA_DESAFIOS = threading.Lock()
DESAFIOS_WEBAUTHN = {}
TRAVA_WEBAUTHN = threading.Lock()


# --------------------------------------------------------------------------- Banco
def carregar_usuarios():
    padrao = {"nome": "presidente marquinhos", "Chave_de_acesso": "marquinhos do grau"}

    if not ARQUIVO_USUARIOS.exists() or ARQUIVO_USUARIOS.stat().st_size == 0:
        ARQUIVO_USUARIOS.write_text(json.dumps(padrao, ensure_ascii=False, indent=2), encoding="utf-8")
        return padrao
    try:
        dados = json.loads(ARQUIVO_USUARIOS.read_text(encoding="utf-8"))
        if isinstance(dados, dict):
            return dados
    except json.JSONDecodeError:
        pass
    ARQUIVO_USUARIOS.write_text(json.dumps(padrao, ensure_ascii=False, indent=2), encoding="utf-8")
    return padrao


def carregar_interacoes():
    if not ARQUIVO_INTERACOES.exists():
        raise FileNotFoundError(f"BD de interações não encontrado: {ARQUIVO_INTERACOES}")
    return json.loads(ARQUIVO_INTERACOES.read_text(encoding="utf-8"))


USUARIOS = carregar_usuarios()
BANCO_DE_DADOS_INTERACOES = carregar_interacoes()


def carregar_passkeys():
    if not ARQUIVO_PASSKEYS.exists():
        return []
    dados = json.loads(ARQUIVO_PASSKEYS.read_text(encoding="utf-8"))
    if not isinstance(dados, list) or not all(isinstance(item, dict) for item in dados):
        raise ValueError(f"Formato inválido no arquivo de passkeys: {ARQUIVO_PASSKEYS}")
    return dados


PASSKEYS = carregar_passkeys()


def salvar_passkeys():
    ARQUIVO_PASSKEYS.write_text(
        json.dumps(PASSKEYS, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def bytes_para_base64url(valor: bytes) -> str:
    return base64.urlsafe_b64encode(valor).rstrip(b"=").decode("ascii")


def configuracao_webauthn():
    origin = os.environ.get("PFC_WEBAUTHN_ORIGIN", request.host_url.rstrip("/"))
    rp_id = os.environ.get("PFC_WEBAUTHN_RP_ID") or urlparse(origin).hostname
    if not rp_id:
        raise RuntimeError("Não foi possível determinar o RP ID do WebAuthn.")
    return rp_id, origin


def cria_desafio_webauthn(
    tipo: str, challenge: bytes, nome: str = "", token_link: str = ""
) -> str:
    agora = obtem_tempo_atual()
    challenge_id = secrets.token_urlsafe(32)
    with TRAVA_WEBAUTHN:
        expirados = [
            identificador for identificador, registro in DESAFIOS_WEBAUTHN.items()
            if agora - registro["criado"] > VALIDADE_DESAFIO_WEBAUTHN_SEGUNDOS
        ]
        for identificador in expirados:
            del DESAFIOS_WEBAUTHN[identificador]
        DESAFIOS_WEBAUTHN[challenge_id] = {
            "tipo": tipo,
            "challenge": bytes_para_base64url(challenge),
            "nome": nome,
            "token_link": token_link,
            "criado": agora,
        }
    return challenge_id


def consome_desafio_webauthn(challenge_id: str, tipo: str):
    with TRAVA_WEBAUTHN:
        registro = DESAFIOS_WEBAUTHN.pop(challenge_id, None)
    if registro is None or registro["tipo"] != tipo:
        return None
    if obtem_tempo_atual() - registro["criado"] > VALIDADE_DESAFIO_WEBAUTHN_SEGUNDOS:
        return None
    return registro


def redirecionamento_apos_login(destino: str):
    if destino.startswith("/verify?"):
        return redirect(destino)
    return redirect(url_for("painel"))


def resposta_webauthn_erro(mensagem: str, status: int):
    return jsonify({"erro": mensagem}), status


def registra_falha_link(token: str):
    with TRAVA_LINKS:
        reg = registro_do_link(token)
        if reg is not None and reg["estado"] == "pendente":
            reg["falhas"] += 1
            if reg["falhas"] >= LIMITE_FALHAS_LINK:
                reg["estado"] = "bloqueado"


def busca_registro_por_identidade(i: str):
    for registro in BANCO_DE_DADOS_INTERACOES.values():
        if registro["identidade_i"] == i:
            return registro
    return None


# --------------------------------------------------------------------------- Desafio
def gera_nonce_aleatorio() -> str:
    return secrets.token_hex(16)


def obtem_tempo_atual() -> int:
    return int(time.time())


def assinar_dados(dados: str, chave_secreta: bytes) -> str:
    return hmac.new(chave_secreta, dados.encode("utf-8"), hashlib.sha256).hexdigest()


def mensagem_do_desafio(nonce: str, ts: int, i: str, ch: str) -> str:
    # Separador evita ambiguidade de concatenação
    return "|".join([nonce, str(ts), i, ch])


def constroi_link_autenticacao(ch: str, i: str, mensagem: str, base_url: str) -> str:
    nonce = gera_nonce_aleatorio()
    timestamp = obtem_tempo_atual()
    assinatura = assinar_dados(mensagem_do_desafio(nonce, timestamp, i, ch), CHAVE_PRIVADA_SISTEMA)

    with TRAVA_DESAFIOS:
        limite = timestamp - 2 * LIMIAR_TEMPO_VALIDADE_SEGUNDOS
        for n in [n for n, d in DESAFIOS.items() if d["ts"] < limite]:
            del DESAFIOS[n]
        DESAFIOS[nonce] = {"i": i, "ts": timestamp, "mensagem": mensagem, "usado": False}

    parametros = {"id": i, "nonce": nonce, "sig": assinatura}
    return f"{base_url.rstrip('/')}/verify?{urlencode(parametros)}"


def valida_assinatura(i: str, nonce: str, ts: int, sig: str, ch: str) -> bool:
    esperada = assinar_dados(mensagem_do_desafio(nonce, ts, i, ch), CHAVE_PRIVADA_SISTEMA)
    return hmac.compare_digest(esperada, sig)


def extrai_contexto(mensagem: str) -> dict:
    return reputacao.extrai_contexto(mensagem)


def calcula_reputacao(i: str, ch: str, contexto: dict) -> dict:
    registro = busca_registro_por_identidade(i)
    if registro is not None and registro["chave_publica_ch"] != ch:
        registro = None
    return reputacao.calcula(registro, contexto)


def processa_mensagem_recebida(remetente_declarado: str, mensagem: str, base_url: str):
    """quando receber mensagem m: busca i e ch no BD e constrói o link de autenticação."""
    dados_autor = BANCO_DE_DADOS_INTERACOES.get(remetente_declarado)
    if not dados_autor:
        return None
    return constroi_link_autenticacao(
        dados_autor["chave_publica_ch"], dados_autor["identidade_i"], mensagem, base_url
    )


# --------------------------------------------------------------------------- Telas / rotas
# --------------------------------------------------------------------------- Link de autenticação aleatório
VALIDADE_LINK_SEGUNDOS = 30
LIMITE_FALHAS_LINK = 1
LINKS = {}   # token -> {"criado", "estado", "nome", "falhas"}; estados: pendente|autenticado|expirado|bloqueado
TRAVA_LINKS = threading.Lock()


def credenciais_validas(nome: str, chave: str) -> bool:
    nome_ok = hmac.compare_digest(str(USUARIOS.get('nome', '')), nome)
    chave_ok = hmac.compare_digest(str(USUARIOS.get('Chave_de_acesso', '')), chave)
    return nome_ok and chave_ok


def cria_link_aleatorio(base_url: str):
    token = secrets.token_urlsafe(32)            # 256 bits de aleatoriedade
    agora = obtem_tempo_atual()
    with TRAVA_LINKS:
        for t in [t for t, r in LINKS.items() if r["criado"] < agora - 2 * VALIDADE_LINK_SEGUNDOS]:
            del LINKS[t]
        LINKS[token] = {"criado": agora, "estado": "pendente", "nome": None, "falhas": 0}
    return token, f"{base_url.rstrip('/')}/auth/{token}"


def registro_do_link(token: str):
    """Chamar com TRAVA_LINKS adquirida. Atualiza expiração e devolve o registro (ou None)."""
    reg = LINKS.get(token)
    if reg is not None and reg["estado"] == "pendente" \
            and obtem_tempo_atual() - reg["criado"] > VALIDADE_LINK_SEGUNDOS:
        reg["estado"] = "expirado"
    return reg


@app.route('/')
def pagina_link():
    """Página 1: gera SEMPRE um link novo e aleatório e aguarda a autenticação."""
    token, link = cria_link_aleatorio(request.host_url)
    return render_template('link.html', token=token, link=link, validade=VALIDADE_LINK_SEGUNDOS)


@app.route('/status/<token>')
def status_link(token):
    """Consultado pela página 1 (polling) para saber se a autenticação foi concluída."""
    with TRAVA_LINKS:
        reg = registro_do_link(token)
        if reg is None:
            resp = jsonify({"estado": "invalido"})
            resp.status_code = 404
        else:
            restante = max(0, VALIDADE_LINK_SEGUNDOS - (obtem_tempo_atual() - reg["criado"]))
            corpo = {"estado": reg["estado"], "restante": restante}
            if reg["estado"] == "autenticado":
                corpo["nome"] = reg["nome"]
            resp = jsonify(corpo)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route('/auth/<token>')
def pagina_autenticacao(token):
    """Página 2: aberta pelo link; exige passkey para concluir a autenticação."""
    with TRAVA_LINKS:
        reg = registro_do_link(token)
        if reg is None:
            return render_template('auth.html', visao='indisponivel', mensagem='Link inválido.'), 404
        if reg["estado"] == "autenticado":
            return render_template('auth.html', visao='indisponivel',
                                   mensagem='Este link já foi utilizado.'), 410
        if reg["estado"] == "expirado":
            return render_template('auth.html', visao='indisponivel',
                                   mensagem='Link expirado. Gere um novo na página inicial.'), 410
        if reg["estado"] == "bloqueado":
            return render_template('auth.html', visao='indisponivel',
                                   mensagem='Link bloqueado por uma autenticação inválida.'), 403

        return render_template(
            'auth.html',
            visao='formulario',
            token=token,
            tem_passkey=bool(PASSKEYS),
        )


@app.route('/auth/<token>/webauthn/opcoes', methods=['POST'])
def opcoes_autenticacao_link(token):
    with TRAVA_LINKS:
        reg = registro_do_link(token)
        if reg is None or reg["estado"] != "pendente":
            return resposta_webauthn_erro("Link inválido, expirado ou já utilizado.", 410)

    if not PASSKEYS:
        return resposta_webauthn_erro(
            "Nenhuma passkey cadastrada. Entre pelo painel, cadastre uma passkey e gere um novo link.",
            409,
        )

    rp_id, _ = configuracao_webauthn()
    opcoes = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(passkey["credential_id"]))
            for passkey in PASSKEYS
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_id = cria_desafio_webauthn(
        "autenticacao_link", opcoes.challenge, token_link=token
    )
    return jsonify({
        "challenge_id": challenge_id,
        "publicKey": json.loads(options_to_json(opcoes)),
    })


@app.route('/auth/<token>/webauthn/verificar', methods=['POST'])
def verificar_autenticacao_link(token):
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict) or not isinstance(dados.get("credential"), dict):
        return resposta_webauthn_erro("Resposta WebAuthn inválida.", 400)

    challenge_id = str(dados.get("challenge_id", ""))
    with TRAVA_WEBAUTHN:
        desafio = DESAFIOS_WEBAUTHN.pop(challenge_id, None)
    if (
        desafio is None
        or desafio["tipo"] != "autenticacao_link"
        or desafio["token_link"] != token
        or obtem_tempo_atual() - desafio["criado"] > VALIDADE_DESAFIO_WEBAUTHN_SEGUNDOS
    ):
        return resposta_webauthn_erro("Desafio inválido, expirado ou já utilizado.", 400)

    credential = dados["credential"]
    credential_id = credential.get("rawId")
    if credential.get("type") != "public-key" or credential.get("id") != credential_id:
        registra_falha_link(token)
        return resposta_webauthn_erro("Resposta WebAuthn inválida.", 400)
    passkey = next(
        (item for item in PASSKEYS if item["credential_id"] == credential_id),
        None,
    )
    if passkey is None:
        registra_falha_link(token)
        return resposta_webauthn_erro("Passkey não reconhecida.", 401)

    rp_id, origin = configuracao_webauthn()
    try:
        verificacao = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(desafio["challenge"]),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(passkey["credential_public_key"]),
            credential_current_sign_count=passkey["sign_count"],
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, TypeError, KeyError):
        registra_falha_link(token)
        return resposta_webauthn_erro("A autenticação com passkey falhou.", 401)

    with TRAVA_LINKS:
        reg = registro_do_link(token)
        if reg is None or reg["estado"] != "pendente":
            return resposta_webauthn_erro("Link inválido, expirado ou já utilizado.", 410)
        reg["estado"] = "autenticado"
        reg["nome"] = passkey["nome"]

    passkey["sign_count"] = verificacao.new_sign_count
    salvar_passkeys()
    return jsonify({"nome": passkey["nome"]})


@app.route('/entrar')
def index():
    return render_template(
        'index.html',
        next=request.args.get('next', ''),
        tem_passkey=bool(PASSKEYS),
    )


@app.route('/login', methods=['POST'])
def login():
    nome = request.form.get('nome', '').strip()
    chave_acesso = request.form.get('chave_acesso', '').strip()
    destino = request.form.get('next', '')

    if PASSKEYS:
        return render_template(
            'index.html',
            erro='Esta conta já está configurada para entrar com passkey.',
            next=destino,
            tem_passkey=True,
        )
    if not nome or not chave_acesso:
        return render_template(
            'index.html',
            erro='Preencha o nome e a chave de acesso.',
            next=destino,
            tem_passkey=False,
        )

    if not credenciais_validas(nome, chave_acesso):
        return render_template(
            'index.html',
            erro='Nome ou chave de acesso inválidos.',
            next=destino,
            tem_passkey=False,
        )

    session.clear()
    session['nome'] = nome
    return redirecionamento_apos_login(destino)


@app.route('/webauthn/autenticacao/opcoes', methods=['POST'])
def opcoes_autenticacao_webauthn():
    if not PASSKEYS:
        return resposta_webauthn_erro(
            "Nenhuma passkey cadastrada. Entre com sua chave atual e cadastre uma passkey no painel.",
            409,
        )

    rp_id, _ = configuracao_webauthn()
    opcoes = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(passkey["credential_id"]))
            for passkey in PASSKEYS
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_id = cria_desafio_webauthn("autenticacao", opcoes.challenge)
    return jsonify({
        "challenge_id": challenge_id,
        "publicKey": json.loads(options_to_json(opcoes)),
    })


@app.route('/webauthn/autenticacao/verificar', methods=['POST'])
def verificar_autenticacao_webauthn():
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict) or not isinstance(dados.get("credential"), dict):
        return resposta_webauthn_erro("Resposta WebAuthn inválida.", 400)

    desafio = consome_desafio_webauthn(
        str(dados.get("challenge_id", "")), "autenticacao"
    )
    if desafio is None:
        return resposta_webauthn_erro("Desafio inválido, expirado ou já utilizado.", 400)

    credential = dados["credential"]
    credential_id = credential.get("rawId")
    if credential.get("type") != "public-key" or credential.get("id") != credential_id:
        return resposta_webauthn_erro("Resposta WebAuthn inválida.", 400)
    passkey = next(
        (item for item in PASSKEYS if item["credential_id"] == credential_id),
        None,
    )
    if passkey is None:
        return resposta_webauthn_erro("Passkey não reconhecida.", 401)

    rp_id, origin = configuracao_webauthn()
    try:
        verificacao = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(desafio["challenge"]),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(passkey["credential_public_key"]),
            credential_current_sign_count=passkey["sign_count"],
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, TypeError, KeyError):
        return resposta_webauthn_erro("A autenticação com passkey falhou.", 401)

    passkey["sign_count"] = verificacao.new_sign_count
    salvar_passkeys()
    session.clear()
    session["nome"] = passkey["nome"]
    destino = str(dados.get("next", ""))
    if destino.startswith("/verify?"):
        proxima_url = destino
    else:
        proxima_url = url_for("painel")
    return jsonify({"redirect": proxima_url})


@app.route('/webauthn/cadastro/opcoes', methods=['POST'])
def opcoes_cadastro_webauthn():
    nome = session.get("nome")
    if not nome:
        return resposta_webauthn_erro("Entre antes de cadastrar uma passkey.", 401)

    rp_id, _ = configuracao_webauthn()
    opcoes = generate_registration_options(
        rp_id=rp_id,
        rp_name="PFC",
        user_id=hashlib.sha256(f"pfc:{nome}".encode("utf-8")).digest(),
        user_name=nome,
        user_display_name=nome,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(item["credential_id"]))
            for item in PASSKEYS
            if item["nome"] == nome
        ],
    )
    challenge_id = cria_desafio_webauthn("cadastro", opcoes.challenge, nome)
    return jsonify({
        "challenge_id": challenge_id,
        "publicKey": json.loads(options_to_json(opcoes)),
    })


@app.route('/webauthn/cadastro/verificar', methods=['POST'])
def verificar_cadastro_webauthn():
    nome = session.get("nome")
    if not nome:
        return resposta_webauthn_erro("Entre antes de cadastrar uma passkey.", 401)

    dados = request.get_json(silent=True)
    if not isinstance(dados, dict) or not isinstance(dados.get("credential"), dict):
        return resposta_webauthn_erro("Resposta WebAuthn inválida.", 400)
    desafio = consome_desafio_webauthn(
        str(dados.get("challenge_id", "")), "cadastro"
    )
    if desafio is None or desafio["nome"] != nome:
        return resposta_webauthn_erro("Desafio inválido, expirado ou já utilizado.", 400)

    rp_id, origin = configuracao_webauthn()
    try:
        verificacao = verify_registration_response(
            credential=dados["credential"],
            expected_challenge=base64url_to_bytes(desafio["challenge"]),
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, TypeError, KeyError):
        return resposta_webauthn_erro("Não foi possível validar esta passkey.", 400)

    credential_id = bytes_para_base64url(verificacao.credential_id)
    if any(item["credential_id"] == credential_id for item in PASSKEYS):
        return resposta_webauthn_erro("Esta passkey já está cadastrada.", 409)
    PASSKEYS.append({
        "nome": nome,
        "credential_id": credential_id,
        "credential_public_key": bytes_para_base64url(verificacao.credential_public_key),
        "sign_count": verificacao.sign_count,
    })
    salvar_passkeys()
    return jsonify({"mensagem": "Passkey cadastrada com sucesso."}), 201


@app.route('/painel')
def painel():
    nome = session.get('nome')
    if not nome:
        return redirect(url_for('index'))
    return render_template(
        'painel.html',
        nome=nome,
        tem_passkey=any(passkey["nome"] == nome for passkey in PASSKEYS),
    )


@app.route('/gerar-link', methods=['GET', 'POST'])
def gerar_link():
    if not session.get('nome'):
        return redirect(url_for('index'))

    ctx = {"remetentes": list(BANCO_DE_DADOS_INTERACOES.keys()),
           "validade": LIMIAR_TEMPO_VALIDADE_SEGUNDOS}

    if request.method == 'GET':
        return render_template('gerar_link.html', **ctx)

    remetente = request.form.get('remetente', '').strip()
    mensagem = request.form.get('mensagem', '').strip()
    link = processa_mensagem_recebida(remetente, mensagem, request.host_url)

    if link is None:
        return render_template('gerar_link.html', **ctx, remetente=remetente, mensagem=mensagem,
                               erro='Identidade não encontrada no Banco de Dados.')
    return render_template('gerar_link.html', **ctx, remetente=remetente, mensagem=mensagem, link=link)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def responde(status, mensagem, http, i=None, resultado=None):
    corpo = {"status": status, "mensagem": mensagem, "identidade": i}
    if resultado is not None:
        corpo["nivel_confianca"] = resultado["nivel"]
        corpo["reputacao"] = resultado
    quer_json = (request.args.get("formato") == "json"
                 or request.accept_mimetypes.best == "application/json")
    if quer_json:
        return jsonify(corpo), http
    return render_template('resultado.html', **corpo), http


@app.route('/verify', methods=['GET'])
def cliente_acessar():
    # O verificador precisa estar autenticado; volta para o link depois do login.
    if not session.get('nome'):
        return redirect(url_for('index', next=request.full_path))

    # (i, nonce, sig) <- extrai_parametros(linkAutenticacao)
    i = request.args.get('id')
    nonce = request.args.get('nonce')
    sig = request.args.get('sig')

    if not all([i, nonce, sig]):
        return responde("erro", "Parâmetros ausentes na requisição", 400)

    with TRAVA_DESAFIOS:
        desafio = DESAFIOS.get(nonce)
        if desafio is None or desafio["i"] != i:
            return responde("alerta_fraude", "Desafio desconhecido ou não emitido por este sistema", 403, i)

        registro = busca_registro_por_identidade(i)
        if registro is None:
            return responde("alerta_fraude", "Identidade não encontrada no BD de interações", 403, i)
        ch = registro["chave_publica_ch"]          # ch vem do BD, não da URL

        # 1. Valida integridade do link
        if not valida_assinatura(i, nonce, desafio["ts"], sig, ch):
            return responde("alerta_fraude", "Assinatura inválida no desafio de autenticação", 403, i)
        if obtem_tempo_atual() - desafio["ts"] > LIMIAR_TEMPO_VALIDADE_SEGUNDOS:
            return responde("alerta_fraude", "Link de autenticação expirado", 401, i)
        if desafio["usado"]:
            return responde("alerta_fraude", "Link já utilizado (possível replay)", 409, i)
        desafio["usado"] = True
        mensagem = desafio["mensagem"]

    # 2. Contexto da comunicação recebida
    contexto = extrai_contexto(mensagem)

    # 3. Máquina de cálculo de reputação
    resultado = calcula_reputacao(i, ch, contexto)

    # 4. Decisão no middleware/sistema
    if resultado["nivel"] < LIMIAR_DE_CONFIANCA:
        return responde("alerta", "Aviso: identidade com baixo nível de confiança ou suspeita de fraude",
                        200, i, resultado)
    return responde("sucesso", f"Identidade '{i}' confirmada com nível de confiança "
                               f"{resultado['classificacao']}.", 200, i, resultado)


if __name__ == "__main__":
    app.run(host=os.environ.get("PFC_HOST", "127.0.0.1"), port=5000,
            debug=os.environ.get("FLASK_DEBUG") == "1")
