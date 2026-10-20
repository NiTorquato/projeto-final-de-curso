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

    def setUp(self):
        super().setUp()
        self.passkeys_originais = main.PASSKEYS.copy()
        main.PASSKEYS[:] = [{
            'nome': 'presidente marquinhos',
            'credential_id': main.bytes_para_base64url(b'link-credential'),
            'credential_public_key': main.bytes_para_base64url(b'link-public-key'),
            'sign_count': 0,
        }]
        main.DESAFIOS_WEBAUTHN.clear()

    def tearDown(self):
        main.PASSKEYS[:] = self.passkeys_originais
        main.DESAFIOS_WEBAUTHN.clear()

    def novo_link(self):
        import re
        r = self.client.get('/')
        self.assertEqual(r.status_code, 200)
        m = re.search(r'/auth/([A-Za-z0-9_-]+)', r.get_data(as_text=True))
        self.assertIsNotNone(m)
        return m.group(1)

    def status(self, token):
        return self.client.get('/status/' + token).get_json()

    def autentica(self, token, valida=True):
        desafio = main.cria_desafio_webauthn(
            'autenticacao_link', b'desafio-link', token_link=token
        )
        credential_id = main.PASSKEYS[0]['credential_id']
        resposta = {
            'challenge_id': desafio,
            'credential': {
                'id': credential_id,
                'rawId': credential_id,
                'type': 'public-key',
            },
        }
        retorno_verificacao = mock.Mock(new_sign_count=1)
        falha = main.WebAuthnException('assinatura inválida')
        with mock.patch.object(
            main,
            'verify_authentication_response',
            return_value=retorno_verificacao if valida else None,
            side_effect=None if valida else falha,
        ), mock.patch.object(main, 'salvar_passkeys'):
            return self.client.post(
                '/auth/' + token + '/webauthn/verificar',
                json=resposta,
            )

    def test_cada_carregamento_gera_link_diferente_e_longo(self):
        a, b = self.novo_link(), self.novo_link()
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a), 40)

    def test_link_abre_pagina_de_autenticacao(self):
        r = self.client.get('/auth/' + self.novo_link())
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'Windows Hello', r.data)
        self.assertNotIn(b'name="chave_acesso"', r.data)

    def test_inicia_pendente(self):
        self.assertEqual(self.status(self.novo_link())['estado'], 'pendente')

    def test_autenticacao_informa_primeira_pagina(self):
        token = self.novo_link()
        r = self.autentica(token)
        self.assertEqual(r.get_json()['nome'], 'presidente marquinhos')
        st = self.status(token)
        self.assertEqual(st['estado'], 'autenticado')
        self.assertEqual(st['nome'], 'presidente marquinhos')

    def test_passkey_invalida_bloqueia_link(self):
        token = self.novo_link()
        r = self.autentica(token, valida=False)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.status(token)['estado'], 'bloqueado')

    def test_bloqueia_apos_tentativas_invalidas(self):
        token = self.novo_link()
        for _ in range(main.LIMITE_FALHAS_LINK):
            self.autentica(token, valida=False)
        self.assertEqual(self.status(token)['estado'], 'bloqueado')
        self.autentica(token)  # mesmo uma assinatura válida não pode reutilizar link bloqueado
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

    def test_link_sem_passkey_cadastrada_nao_pede_senha(self):
        main.PASSKEYS.clear()
        token = self.novo_link()
        pagina = self.client.get('/auth/' + token)
        self.assertEqual(pagina.status_code, 200)
        self.assertIn(b'Nenhuma passkey foi cadastrada', pagina.data)
        self.assertNotIn(b'name="chave_acesso"', pagina.data)
        resposta = self.client.post('/auth/' + token + '/webauthn/opcoes')
        self.assertEqual(resposta.status_code, 409)

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


class WebAuthnTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.passkeys_originais = main.PASSKEYS.copy()
        main.PASSKEYS.clear()
        main.DESAFIOS_WEBAUTHN.clear()

    def tearDown(self):
        main.PASSKEYS[:] = self.passkeys_originais
        main.DESAFIOS_WEBAUTHN.clear()

    def test_opcoes_de_login_sem_passkey_exibem_instrucao(self):
        resposta = self.client.post('/webauthn/autenticacao/opcoes')
        self.assertEqual(resposta.status_code, 409)
        self.assertIn('cadastre uma passkey', resposta.get_json()['erro'])

    @mock.patch.object(main, 'options_to_json', return_value='{}')
    @mock.patch.object(main, 'generate_authentication_options')
    def test_login_com_passkey_valida_desafio_e_inicia_sessao(
        self, gerar_opcoes, _options_to_json
    ):
        gerar_opcoes.return_value.challenge = b'desafio-autenticacao'
        main.PASSKEYS.append({
            'nome': 'presidente marquinhos',
            'credential_id': main.bytes_para_base64url(b'credencial'),
            'credential_public_key': main.bytes_para_base64url(b'chave-publica'),
            'sign_count': 0,
        })
        resposta_opcoes = self.client.post('/webauthn/autenticacao/opcoes')
        self.assertEqual(resposta_opcoes.status_code, 200)
        dados_opcoes = resposta_opcoes.get_json()
        self.assertIn(dados_opcoes['challenge_id'], main.DESAFIOS_WEBAUTHN)

        with mock.patch.object(
            main, 'verify_authentication_response',
            return_value=mock.Mock(new_sign_count=1),
        ) as verificar, mock.patch.object(main, 'salvar_passkeys'):
            resposta_login = self.client.post(
                '/webauthn/autenticacao/verificar',
                json={
                    'challenge_id': dados_opcoes['challenge_id'],
                    'credential': {
                        'id': main.PASSKEYS[0]['credential_id'],
                        'rawId': main.PASSKEYS[0]['credential_id'],
                        'type': 'public-key',
                    },
                    'next': '/verify?id=1',
                },
            )

        self.assertEqual(resposta_login.status_code, 200)
        self.assertEqual(resposta_login.get_json()['redirect'], '/verify?id=1')
        self.assertEqual(verificar.call_args.kwargs['expected_challenge'], b'desafio-autenticacao')
        with self.client.session_transaction() as sessao:
            self.assertEqual(sessao['nome'], 'presidente marquinhos')

        repetida = self.client.post(
            '/webauthn/autenticacao/verificar',
            json={
                'challenge_id': dados_opcoes['challenge_id'],
                'credential': {
                    'id': main.PASSKEYS[0]['credential_id'],
                    'rawId': main.PASSKEYS[0]['credential_id'],
                    'type': 'public-key',
                },
            },
        )
        self.assertEqual(repetida.status_code, 400)

    def test_login_por_senha_e_bloqueado_depois_do_cadastro(self):
        main.PASSKEYS.append({
            'nome': 'presidente marquinhos',
            'credential_id': 'id-cadastrado',
            'credential_public_key': 'chave-publica',
            'sign_count': 0,
        })
        resposta = self.client.post(
            '/login',
            data={'nome': 'presidente marquinhos', 'chave_acesso': 'marquinhos do grau'},
        )
        self.assertEqual(resposta.status_code, 200)
        self.assertIn('configurada para entrar com passkey'.encode(), resposta.data)
        self.assertNotIn(b'name="chave_acesso"', resposta.data)

    @mock.patch.object(main, 'options_to_json', return_value='{}')
    @mock.patch.object(main, 'generate_registration_options')
    def test_cadastro_de_passkey_exige_sessao_e_persiste_credencial(
        self, gerar_opcoes, _options_to_json
    ):
        self.assertEqual(self.client.post('/webauthn/cadastro/opcoes').status_code, 401)
        self.login()

        gerar_opcoes.return_value.challenge = b'desafio-cadastro'
        resposta_opcoes = self.client.post('/webauthn/cadastro/opcoes')
        self.assertEqual(resposta_opcoes.status_code, 200)
        challenge_id = resposta_opcoes.get_json()['challenge_id']

        with mock.patch.object(
            main, 'verify_registration_response',
            return_value=mock.Mock(
                credential_id=b'nova-credencial',
                credential_public_key=b'chave-publica',
                sign_count=0,
            ),
        ) as verificar, mock.patch.object(main, 'salvar_passkeys') as salvar:
            resposta = self.client.post(
                '/webauthn/cadastro/verificar',
                json={
                    'challenge_id': challenge_id,
                    'credential': {'id': 'nova-credencial'},
                },
            )

        self.assertEqual(resposta.status_code, 201)
        self.assertEqual(verificar.call_args.kwargs['expected_challenge'], b'desafio-cadastro')
        self.assertEqual(main.PASSKEYS[0]['nome'], 'presidente marquinhos')
        self.assertEqual(main.PASSKEYS[0]['credential_id'], main.bytes_para_base64url(b'nova-credencial'))
        salvar.assert_called_once()


if __name__ == '__main__':
    unittest.main()
