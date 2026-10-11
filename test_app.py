import unittest
from unittest import mock

import main
import reputacao
from main import app


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def login(self):
        self.client.post('/login', data={'nome': 'presidente marquinhos',
                                         'chave_acesso': 'marquinhos do grau'})

    def link(self, remetente='presidente_empresa', mensagem='ola'):
        url = main.processa_mensagem_recebida(remetente, mensagem, 'http://localhost/')
        return url.replace('http://localhost', '')

    def verifica(self, link):
        return self.client.get(link + '&formato=json')


class LinkAleatorioTestCase(BaseTestCase):
    """Página 1 gera link aleatório -> página 2 autentica -> página 1 é informada."""

    def novo_link(self):
        import re
        r = self.client.get('/')
        self.assertEqual(r.status_code, 200)
        m = re.search(r'/auth/([A-Za-z0-9_-]+)', r.get_data(as_text=True))
        self.assertIsNotNone(m)
        return m.group(1)

    def status(self, token):
        return self.client.get('/status/' + token).get_json()

    def autentica(self, token, nome='presidente marquinhos', chave='marquinhos do grau'):
        return self.client.post('/auth/' + token, data={'nome': nome, 'chave_acesso': chave})

    def test_cada_carregamento_gera_link_diferente_e_longo(self):
        a, b = self.novo_link(), self.novo_link()
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a), 40)

    def test_link_abre_pagina_de_autenticacao(self):
        r = self.client.get('/auth/' + self.novo_link())
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'Chave de acesso', r.data)

    def test_inicia_pendente(self):
        self.assertEqual(self.status(self.novo_link())['estado'], 'pendente')

    def test_autenticacao_informa_primeira_pagina(self):
        token = self.novo_link()
        r = self.autentica(token)
        self.assertIn('Autenticação concluída'.encode(), r.data)
        st = self.status(token)
        self.assertEqual(st['estado'], 'autenticado')
        self.assertEqual(st['nome'], 'presidente marquinhos')

    def test_credenciais_erradas_mantem_pendente(self):
        token = self.novo_link()
        r = self.autentica(token, chave='errada')
        self.assertIn(b'Tentativas restantes: 4', r.data)
        self.assertEqual(self.status(token)['estado'], 'pendente')

    def test_bloqueia_apos_tentativas_invalidas(self):
        token = self.novo_link()
        for _ in range(main.LIMITE_FALHAS_LINK):
            self.autentica(token, chave='errada')
        self.assertEqual(self.status(token)['estado'], 'bloqueado')
        self.autentica(token)  # mesmo com a senha certa, continua bloqueado
        self.assertEqual(self.status(token)['estado'], 'bloqueado')

    def test_link_e_de_uso_unico(self):
        token = self.novo_link()
        self.autentica(token)
        r = self.client.get('/auth/' + token)
        self.assertEqual(r.status_code, 410)
        self.assertIn(b'j\xc3\xa1 foi utilizado', r.data)

    def test_link_expira(self):
        token = self.novo_link()
        futuro = main.obtem_tempo_atual() + main.VALIDADE_LINK_SEGUNDOS + 10
        with mock.patch.object(main, 'obtem_tempo_atual', return_value=futuro):
            self.assertEqual(self.status(token)['estado'], 'expirado')
            self.assertEqual(self.client.get('/auth/' + token).status_code, 410)
            self.autentica(token)
            self.assertEqual(self.status(token)['estado'], 'expirado')

    def test_token_inexistente(self):
        self.assertEqual(self.client.get('/auth/inventado').status_code, 404)
        r = self.client.get('/status/inventado')
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json()['estado'], 'invalido')

    def test_tokens_sao_independentes(self):
        a, b = self.novo_link(), self.novo_link()
        self.autentica(a)
        self.assertEqual(self.status(a)['estado'], 'autenticado')
        self.assertEqual(self.status(b)['estado'], 'pendente')


class LoginTestCase(BaseTestCase):
    def test_pagina_login_exibe_campos(self):
        r = self.client.get('/entrar')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'Nome', r.data)
        self.assertIn(b'Chave de acesso', r.data)

    def test_login_com_dados_validos(self):
        r = self.client.post('/login', data={'nome': 'presidente marquinhos',
                                             'chave_acesso': 'marquinhos do grau'}, follow_redirects=True)
        self.assertIn(b'Seja bem-vindo', r.data)

    def test_login_com_dados_invalidos(self):
        r = self.client.post('/login', data={'nome': 'presidente marquinhos', 'chave_acesso': 'errada'})
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'Nome ou chave de acesso inv', r.data)

    def test_login_nao_redireciona_para_destino_externo(self):
        r = self.client.post('/login', data={'nome': 'presidente marquinhos',
                                             'chave_acesso': 'marquinhos do grau',
                                             'next': 'http://evil.com'})
        self.assertTrue(r.headers['Location'].endswith('/painel'))


class GerarLinkTestCase(BaseTestCase):
    def test_exige_login(self):
        self.assertEqual(self.client.get('/gerar-link').status_code, 302)

    def test_exibe_link_na_tela(self):
        self.login()
        r = self.client.post('/gerar-link', data={'remetente': 'presidente_empresa', 'mensagem': 'oi'})
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'/verify?', r.data)

    def test_remetente_inexistente(self):
        self.login()
        r = self.client.post('/gerar-link', data={'remetente': 'fantasma'})
        self.assertIn(b'Identidade n', r.data)
        self.assertNotIn(b'/verify?', r.data)

    def test_link_nao_expoe_chave_publica(self):
        self.assertNotIn('pubkey', self.link())


class VerifyTestCase(BaseTestCase):
    def test_exige_login_e_volta_ao_link(self):
        link = self.link()
        r = self.client.get(link)
        self.assertEqual(r.status_code, 302)
        self.assertIn('next=', r.headers['Location'])
        # após o login, redireciona de volta para a verificação
        r = self.client.post('/login', data={'nome': 'presidente marquinhos',
                                             'chave_acesso': 'marquinhos do grau', 'next': link})
        self.assertTrue(r.headers['Location'].startswith('/verify?'))

    def test_sucesso_identidade_confiavel(self):
        self.login()
        r = self.verifica(self.link())
        self.assertEqual(r.status_code, 200)
        dados = r.get_json()
        self.assertEqual(dados['status'], 'sucesso')
        self.assertGreaterEqual(dados['nivel_confianca'], 80)

    def test_tela_de_resultado_html(self):
        self.login()
        r = self.client.get(self.link())
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'Por que este n', r.data)

    def test_replay_bloqueado(self):
        self.login()
        link = self.link()
        self.assertEqual(self.verifica(link).status_code, 200)
        self.assertEqual(self.verifica(link).status_code, 409)

    def test_assinatura_adulterada(self):
        self.login()
        link = self.link()
        r = self.verifica(link.replace('sig=', 'sig=00'))
        self.assertEqual(r.status_code, 403)

    def test_expirado(self):
        self.login()
        link = self.link()
        futuro = main.obtem_tempo_atual() + main.LIMIAR_TEMPO_VALIDADE_SEGUNDOS + 10
        with mock.patch.object(main, 'obtem_tempo_atual', return_value=futuro):
            r = self.verifica(link)
        self.assertEqual(r.status_code, 401)

    def test_nonce_inventado(self):
        self.login()
        r = self.client.get('/verify?id=id_pres_001&nonce=abc&sig=def&formato=json')
        self.assertEqual(r.status_code, 403)

    def test_parametros_ausentes(self):
        self.login()
        self.assertEqual(self.client.get('/verify?id=x&formato=json').status_code, 400)

    def test_conta_suspeita_gera_alerta(self):
        self.login()
        dados = self.verifica(self.link('conta_suspeita')).get_json()
        self.assertEqual(dados['status'], 'alerta')
        self.assertLess(dados['nivel_confianca'], reputacao.LIMIAR_DE_CONFIANCA)

    def test_url_suspeita_reduz_nivel(self):
        self.login()
        limpo = self.verifica(self.link(mensagem='bom dia')).get_json()['nivel_confianca']
        sujo = self.verifica(self.link(mensagem='pague em http://192.168.0.10/pix')).get_json()
        self.assertLess(sujo['nivel_confianca'], limpo)
        self.assertEqual(sujo['status'], 'alerta')


class ReputacaoTestCase(unittest.TestCase):
    def test_identidade_inexistente(self):
        r = reputacao.calcula(None, {"urls": []})
        self.assertEqual(r['nivel'], 0)

    def test_sem_evidencias_nao_e_confiavel(self):
        r = reputacao.calcula({"dominios_conhecidos": []}, {"urls": []})
        self.assertEqual(r['nivel'], reputacao.BASE_SEM_EVIDENCIAS)
        self.assertEqual(r['classificacao'], 'baixo')

    def test_dominio_conhecido_nao_penaliza(self):
        f, _ = reputacao.avalia_contexto({"urls": ["https://app.empresa.com.br/x"]}, ["empresa.com.br"])
        self.assertEqual(f, 1.0)

    def test_dominio_parecido_e_penalizado(self):
        f, _ = reputacao.avalia_contexto({"urls": ["https://empresa.com.br.golpe.xyz/x"]}, ["empresa.com.br"])
        self.assertLess(f, 1.0)


if __name__ == '__main__':
    unittest.main()
