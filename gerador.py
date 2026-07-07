import sqlite3
import string
import secrets
import os
from cryptography.fernet import Fernet, InvalidToken

DB_NAME = "gerenciador_senhas.db"
KEY_FILE = "chave.key"




def gerar_senha(comprimento=16, incluir_maiusculas=True, incluir_numeros=True, incluir_especiais=True):
    if comprimento < (incluir_maiusculas + incluir_numeros + incluir_especiais + 1):
        raise ValueError("O comprimento é muito curto para as opções selecionadas.")

    senha_obrigatoria = [secrets.choice(string.ascii_lowercase)]
    caracteres_pool = string.ascii_lowercase

    if incluir_maiusculas:
        senha_obrigatoria.append(secrets.choice(string.ascii_uppercase))
        caracteres_pool += string.ascii_uppercase
    if incluir_numeros:
        senha_obrigatoria.append(secrets.choice(string.digits))
        caracteres_pool += string.digits
    if incluir_especiais:
        senha_obrigatoria.append(secrets.choice(string.punctuation))
        caracteres_pool += string.punctuation

    comprimento_restante = comprimento - len(senha_obrigatoria)
    senha_restante = [secrets.choice(caracteres_pool) for _ in range(comprimento_restante)]

    senha_completa = senha_obrigatoria + senha_restante
    secrets.SystemRandom().shuffle(senha_completa)

    return ''.join(senha_completa)


def obter_chave_criptografia():
    if not os.path.exists(KEY_FILE):
        chave = Fernet.generate_key()
        with open(KEY_FILE, "wb") as arquivo_chave:
            arquivo_chave.write(chave)
    else:
        with open(KEY_FILE, "rb") as arquivo_chave:
            chave = arquivo_chave.read()
    return Fernet(chave)


def inicializar_banco():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credenciais (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                servico TEXT NOT NULL,
                usuario TEXT NOT NULL,
                senha_criptografada TEXT NOT NULL
            )
        ''')


def salvar_senha(servico, usuario, senha_pura, cipher):
    senha_cripto = cipher.encrypt(senha_pura.encode()).decode()

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO credenciais (servico, usuario, senha_criptografada)
            VALUES (?, ?, ?)
        ''', (servico, usuario, senha_cripto))


def listar_senhas(cipher):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT servico, usuario, senha_criptografada FROM credenciais')
        linhas = cursor.fetchall()

    if not linhas:
        print("\nNenhuma senha salva ainda.")
        return

    print("\n=== SUAS SENHAS SALVAS ===")
    for linha in linhas:
        servico, usuario, senha_cripto = linha

  
        try:
            senha_descriptografada = cipher.decrypt(senha_cripto.encode()).decode()
            print(f"Serviço: {servico} | Usuário: {usuario} | Senha: {senha_descriptografada}")
        except InvalidToken:
            print(f"Serviço: {servico} | Usuário: {usuario} | "
                  f"⚠️  Não foi possível descriptografar (chave inválida ou dado corrompido).")


def ler_comprimento_senha():
    """
    2. Validação no input do usuário: garante que o comprimento informado
    é um inteiro válido, sem derrubar o programa com um erro não tratado.
    """
    entrada = input("Comprimento da senha (padrão 16): ").strip()

    if entrada == "":
        return 16

    try:
        comprimento = int(entrada)
    except ValueError:
        print("Valor inválido. Utilizando o comprimento padrão (16).")
        return 16

    if comprimento <= 0:
        print("O comprimento deve ser positivo. Utilizando o comprimento padrão (16).")
        return 16

    return comprimento


if __name__ == "__main__":
    inicializar_banco()
    gerenciador_cripto = obter_chave_criptografia()

    while True:
        print("\n*** GERENCIADOR E GERADOR DE SENHAS ***")
        print("1. Gerar e Salvar Nova Senha")
        print("2. Visualizar Senhas Salvas")
        print("3. Sair")

        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            servico = input("Nome do serviço (ex: Netflix, Github): ")
            usuario = input("Nome de usuário/E-mail: ")

            comp = ler_comprimento_senha()

            try:
                senha_gerada = gerar_senha(comprimento=comp)
                salvar_senha(servico, usuario, senha_gerada, gerenciador_cripto)
                print(f"\nSenha gerada com sucesso para '{servico}': {senha_gerada}")
                print("Ela foi criptografada e salva com segurança no banco de dados!")
            except ValueError as e:
                print(f"Erro: {e}")

        elif opcao == "2":
            listar_senhas(gerenciador_cripto)

        elif opcao == "3":
            print("Saindo... ")
            break
        else:
            print("Opção inválida. Tente novamente.")