"""Máquina de cálculo de reputação (protótipo do PFC).

Entrada : registro da identidade no BD de interações + contexto da mensagem.
Saída   : nível de confiança (0-100), classificação e explicação (motivos).

Modelo:
  1. Fontes de reputação da identidade (cada uma 0-100, ou None se não houver dado):
       - direta        : histórico local de interações (média suavizada - penalidade por incidente)
       - web_of_trust  : média ponderada da confiança dada por peers
       - hierarquica   : status do vínculo com uma autoridade (ex.: OAuth/diretório)
     base = média ponderada apenas das fontes disponíveis (pesos renormalizados).
     Sem nenhuma evidência, base = BASE_SEM_EVIDENCIAS (desconhecido não é confiável).
  2. Fator de contexto (0-1): penalidades por URLs suspeitas na mensagem.
  3. nível = round(base * fator_contexto)

ATENÇÃO: pesos, penalidades e faixas abaixo são escolhas do protótipo, não resultados
validados. Devem ser justificados (ou calibrados) com a literatura no texto do PFC.
"""
import re
from urllib.parse import urlparse

LIMIAR_DE_CONFIANCA = 50          # abaixo disso: alerta ao usuário
LIMIAR_ALTO = 80                  # a partir daí: confiança alta
PESOS_FONTES = {"direta": 0.5, "web_of_trust": 0.25, "hierarquica": 0.25}
PENALIDADE_INCIDENTE = 15
BASE_SEM_EVIDENCIAS = 25

ENCURTADORES = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
STATUS_AUTORIDADE = {"valido": 100, "pendente": 50, "revogado": 0}


def extrai_contexto(mensagem: str) -> dict:
    """Extrai metadados da mensagem m (por ora: tamanho e URLs)."""
    urls = [u.rstrip(".,;:!?)]}>\"'") for u in re.findall(r"https?://[^\s]+", mensagem)]
    return {"origem": "mensagem_recebida", "tamanho": len(mensagem), "urls": urls}


def classifica(nivel: int) -> str:
    if nivel >= LIMIAR_ALTO:
        return "alto"
    if nivel >= LIMIAR_DE_CONFIANCA:
        return "médio"
    return "baixo"


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


def confianca_direta(registro: dict):
    h = registro.get("historico") or {}
    total = h.get("interacoes", 0)
    if total <= 0:
        return None, None
    ok, inc = h.get("confiaveis", 0), h.get("incidentes", 0)
    score = _clamp((ok + 1) / (total + 2) * 100 - inc * PENALIDADE_INCIDENTE)
    return score, f"Histórico direto: {ok}/{total} interações confiáveis, {inc} incidente(s)."


def web_of_trust(registro: dict):
    peers = registro.get("peers") or []
    soma = sum(p["peso"] for p in peers)
    if not peers or soma <= 0:
        return None, None
    score = _clamp(sum(p["confianca"] * p["peso"] for p in peers) / soma)
    return score, f"Web of trust: {len(peers)} peer(s), confiança ponderada {score:.0f}."


def hierarquica(registro: dict):
    a = registro.get("autoridade")
    if not a or a.get("status") not in STATUS_AUTORIDADE:
        return None, None
    return float(STATUS_AUTORIDADE[a["status"]]), f"Autoridade '{a.get('nome', '?')}': vínculo {a['status']}."


def avalia_contexto(contexto: dict, dominios_conhecidos: list):
    fator, motivos = 1.0, []
    for url in contexto.get("urls", []):
        host = (urlparse(url).hostname or "").lower()
        if not host:
            continue
        p = []
        if urlparse(url).scheme != "https":
            fator -= 0.10; p.append("sem HTTPS")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            fator -= 0.30; p.append("endereço IP literal")
        if host in ENCURTADORES:
            fator -= 0.25; p.append("encurtador de URL")
        if "xn--" in host:
            fator -= 0.25; p.append("domínio punycode")
        if not any(host == d or host.endswith("." + d) for d in dominios_conhecidos):
            fator -= 0.25; p.append("domínio não associado à identidade")
        if p:
            motivos.append(f"URL {url}: " + ", ".join(p) + ".")
    return max(0.0, round(fator, 2)), motivos


def calcula(registro, contexto: dict) -> dict:
    fontes = {"direta": None, "web_of_trust": None, "hierarquica": None}
    if registro is None:
        return {"nivel": 0, "classificacao": "baixo", "base": 0, "fator_contexto": 1.0,
                "fontes": fontes, "motivos": ["Identidade não encontrada no BD de interações."]}

    motivos = []
    for nome, fn in (("direta", confianca_direta), ("web_of_trust", web_of_trust), ("hierarquica", hierarquica)):
        score, motivo = fn(registro)
        fontes[nome] = None if score is None else round(score)
        if motivo:
            motivos.append(motivo)

    disp = {k: v for k, v in fontes.items() if v is not None}
    if disp:
        base = sum(PESOS_FONTES[k] * v for k, v in disp.items()) / sum(PESOS_FONTES[k] for k in disp)
    else:
        base = BASE_SEM_EVIDENCIAS
        motivos.append("Nenhuma evidência de reputação disponível para esta identidade.")

    fator, motivos_ctx = avalia_contexto(contexto, registro.get("dominios_conhecidos", []))
    motivos += motivos_ctx
    nivel = round(base * fator)
    return {"nivel": nivel, "classificacao": classifica(nivel), "base": round(base),
            "fator_contexto": fator, "fontes": fontes, "motivos": motivos}
