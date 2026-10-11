import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

import reputacao

app = Flask(__name__)
app.secret_key = os.environ.get("PFC_SECRET_KEY", "chave-secreta-do-projeto")

BASE_DIR = Path(__file__).resolve().parent
BANCO_DIR = BASE_DIR / "Banco"
BANCO_DIR.mkdir(exist_ok=True)
ARQUIVO_USUARIOS = BANCO_DIR / "autenticacao.json"
ARQUIVO_INTERACOES = BANCO_DIR / "interacoes.json"

CHAVE_PRIVADA_SISTEMA = os.environ.get("PFC_CHAVE_SISTEMA", "chave_secreta_do_middleware_pfc").encode("utf-8")
LIMIAR_TEMPO_VALIDADE_SEGUNDOS = 300
LIMIAR_DE_CONFIANCA = reputacao.LIMIAR_DE_CONFIANCA

# Desafios emitidos (nonce -> registro). Em memória: somem ao reiniciar o servidor.
DESAFIOS = {}
TRAVA_DESAFIOS = threading.Lock()


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
VALIDADE_LINK_SEGUNDOS = 300
LIMITE_FALHAS_LINK = 5
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


@app.route('/auth/<token>', methods=['GET', 'POST'])
def pagina_autenticacao(token):
    """Página 2: aberta pelo link; pede nome e chave e, se corretos, conclui a autenticação."""
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
                                   mensagem='Link bloqueado por tentativas inválidas.'), 403

        if request.method == 'GET':
            return render_template('auth.html', visao='formulario', token=token)

        nome = request.form.get('nome', '').strip()
        chave = request.form.get('chave_acesso', '').strip()
        if nome and chave and credenciais_validas(nome, chave):
            reg["estado"] = "autenticado"
            reg["nome"] = nome
            return render_template('auth.html', visao='concluido', nome=nome)

        reg["falhas"] += 1
        if reg["falhas"] >= LIMITE_FALHAS_LINK:
            reg["estado"] = "bloqueado"
            return render_template('auth.html', visao='indisponivel',
                                   mensagem='Muitas tentativas inválidas. Link bloqueado.'), 403
        restantes = LIMITE_FALHAS_LINK - reg["falhas"]
        return render_template('auth.html', visao='formulario', token=token,
                               erro=f'Nome ou chave de acesso inválidos. Tentativas restantes: {restantes}.')


@app.route('/entrar')
def index():
    return render_template('index.html', next=request.args.get('next', ''))


@app.route('/login', methods=['POST'])
def login():
    nome = request.form.get('nome', '').strip()
    chave_acesso = request.form.get('chave_acesso', '').strip()
    destino = request.form.get('next', '')

    if not nome or not chave_acesso:
        return render_template('index.html', erro='Preencha o nome e a chave de acesso.', next=destino)

    if not credenciais_validas(nome, chave_acesso):
        return render_template('index.html', erro='Nome ou chave de acesso inválidos.', next=destino)

    session['nome'] = nome
    if destino.startswith('/verify?'):   # só aceita destino interno de verificação
        return redirect(destino)
    return redirect(url_for('painel'))


@app.route('/painel')
def painel():
    nome = session.get('nome')
    if not nome:
        return redirect(url_for('index'))
    return render_template('painel.html', nome=nome)


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
