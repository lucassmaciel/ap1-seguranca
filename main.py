# Importando as bibliotecas necessárias
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

BYTES = 32
class ChaCha20Cipher:
    """
    Esta classe encapsula a lógica para criptografar e autenticar mensagens
    usando o algoritmo ChaCha20 com o autenticador Poly1305 (AEAD).
    """

    def __init__(self, key):
        """
        O construtor da classe.

        Args:
            key (bytes): A chave secreta. Para ChaCha20, deve ter 32 bytes (256 bits).
        """
        # ChaCha20 exige uma chave de 256 bits (32 bytes)
        if len(key) != BYTES:
            raise ValueError("A chave ChaCha20 deve ter exatamente 32 bytes.")
        self.key = key

    def encrypt(self, plain_text):
        """
        Criptografa e autentica uma mensagem de texto plano.

        Args:
            plain_text (str): A mensagem que você quer proteger.

        Returns:
            bytes: A mensagem criptografada, combinando nonce, tag e o texto cifrado.
                   Formato: [12 bytes de nonce][16 bytes de tag][texto cifrado]
        """
        plain_text_bytes = plain_text.encode("utf-8")

        # Criamos um novo cifrador. Para ChaCha20-Poly1305, a biblioteca pycryptodome
        # nos dá um objeto que já une os dois.
        cipher = ChaCha20_Poly1305.new(key=self.key)

        # Criptografamos e geramos o 'tag' de autenticação em um só passo.
        # O nonce é gerado internamente e fica disponível no atributo cipher.nonce
        cipher_text, tag = cipher.encrypt_and_digest(plain_text_bytes)

        # O nonce do ChaCha20 tem 12 bytes e o tag do Poly1305 tem 16 bytes.
        # Nós os retornamos juntos para que a descriptografia possa usá-los.
        return cipher.nonce + tag + cipher_text

    def decrypt(self, encrypted_message):
        """
        Descriptografa e verifica a autenticidade de uma mensagem.

        Args:
            encrypted_message (bytes): A mensagem criptografada do método encrypt().

        Returns:
            str: A mensagem original, se a verificação for bem-sucedida.
            None: Se a mensagem foi adulterada (verificação falhou).
        """
        try:
            # Separamos o nonce (12 bytes), o tag (16 bytes) e o texto cifrado.
            nonce = encrypted_message[:12]
            tag = encrypted_message[12:28]
            cipher_text = encrypted_message[28:]

            # Criamos o cifrador com a mesma chave e o nonce extraído.
            cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)

            # Descriptografamos e VERIFICAMOS a mensagem.
            # Se o tag não for válido, a biblioteca levantará uma exceção ValueError.
            decrypted_bytes = cipher.decrypt_and_verify(cipher_text, tag)

            return decrypted_bytes.decode("utf-8")
        except (ValueError, KeyError):
            # A exceção indica que a autenticação falhou!
            print("Erro de descriptografia: A mensagem é inválida ou foi adulterada!")
            return None


# --- Exemplo de Uso ---
if __name__ == "__main__":
    print("--- Testando o Módulo de Criptografia ChaCha20-Poly1305 ---")

    # 1. Gerar uma chave secreta de 32 bytes (256 bits).
    secret_key = get_random_bytes(BYTES)
    cipher_manager = ChaCha20Cipher(secret_key)

    minha_mensagem = (
        "ChaCha20-Poly1305 é o padrão de ouro para criptografia em software."
    )
    print(f"\nMensagem Original: '{minha_mensagem}'")

    # 2. Criptografar a mensagem.
    mensagem_criptografada = cipher_manager.encrypt(minha_mensagem)
    print(f"\nMensagem Criptografada (bytes): {mensagem_criptografada}")

    # 3. Descriptografar a mensagem (caminho feliz).
    mensagem_descriptografada = cipher_manager.decrypt(mensagem_criptografada)
    if mensagem_descriptografada:
        print(f"\nMensagem Descriptografada: '{mensagem_descriptografada}'")
        if minha_mensagem == mensagem_descriptografada:
            print("✅ Sucesso! A verificação de integridade passou.")

    # 4. Teste de adulteração (simulando um ataque).
    print("\n--- Simulando uma adulteração na mensagem ---")
    # Trocamos um byte no meio da mensagem criptografada
    posicao_adulterada = len(mensagem_criptografada) // 2
    mensagem_adulterada = (
        mensagem_criptografada[:posicao_adulterada]
        + b"!"
        + mensagem_criptografada[posicao_adulterada + 1 :]
    )

    # Tentamos descriptografar a mensagem adulterada.
    # O método decrypt() deve retornar None e imprimir um erro.
    resultado_adulterado = cipher_manager.decrypt(mensagem_adulterada)
    if resultado_adulterado is None:
        print("✅ Sucesso! A adulteração foi detectada e a descriptografia bloqueada.")
