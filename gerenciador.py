import sqlite3
import string
import secrets
import os
from cryptography.fernet import Fernet, InvalidToken

DB_NAME = "gerenciador_senhas.db"
KEY_FILE = "chave.key"


def gerar_senha(comprimento=16):
    if comprimento < 4:
        raise ValueError("O comprimento mínimo para uma senha segura é 4 caracteres.")

    leiras_minusculas = string.ascii_lowercase
    leiras_maiusculas = string.ascii_uppercase
    digitos = string.digits
    especiais = "!@#$%^&*()-_=+"

    todos_caracteres = leiras_minusculas + leiras_maiusculas + digitos + especiais

    senha = [
        secrets.choice(leiras_minusculas),
        secrets.choice(leiras_maiusculas),
        secrets.choice(digitos),
        secrets.choice(especiais)
    ]

    senha += [secrets.choice(todos_caracteres) for _ in range(comprimento - 4)]
    secrets.SystemRandom().shuffle(senha)

    return "".join(senha)


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
                  f" Não foi possível descriptografar (chave inválida ou dado corrompido).")


def apagar_senha(servico, usuario):
    
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
       
        cursor.execute('''
            DELETE FROM credenciais 
            WHERE LOWER(servico) = LOWER(?) AND LOWER(usuario) = LOWER(?)
        ''', (servico, usuario))
        
        
        if cursor.rowcount > 0:
            print(f"\nSucesso: A credencial para '{servico}' ({usuario}) foi apagada.")
        else:
            print(f"\nErro: Nenhuma credencial encontrada para '{servico}' com o usuário '{usuario}'.")


def ler_comprimento_senha():
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
        print("3. Apagar Senha Salva")
        print("4. Sair")

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
            servico = input("Nome do serviço (ex: Netflix, Github): ")
            usuario = input("Nome de usuário/E-mail: ")
            apagar_senha(servico, usuario)

        elif opcao == "4":
            print("Saindo... ")
            break
        else:
            print("Opção inválida. Tente novamente.")