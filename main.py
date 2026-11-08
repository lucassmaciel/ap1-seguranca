from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class Salsa20Confidentiality:
    KEY_SIZE = 32
    # CORREÇÃO: O nonce para a biblioteca pycryptodome deve ser de 8 bytes.
    NONCE_SIZE = 8

    def __init__(self, shared_key: bytes):
        if len(shared_key) != self.KEY_SIZE:
            msg = f"Erro: A chave deve ter exatamente {self.KEY_SIZE} bytes."
            raise ValueError(
                msg
            )
        self.shared_key = shared_key

    def encrypt(self, plaintext: str) -> bytes:
        nonce = get_random_bytes(self.NONCE_SIZE)
        cipher = Salsa20.new(key=self.shared_key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
        return nonce + ciphertext

    def decrypt(self, packet: bytes) -> str | None:
        if len(packet) < self.NONCE_SIZE:
            return None
        try:
            nonce = packet[: self.NONCE_SIZE]
            ciphertext = packet[self.NONCE_SIZE :]
            cipher = Salsa20.new(key=self.shared_key, nonce=nonce)
            decrypted_bytes = cipher.decrypt(ciphertext)
            return decrypted_bytes.decode("utf-8")
        except KeyError:
            return None


# --- SIMULAÇÃO DO ACORDO DE CHAVE ECDH (sem alterações) ---

if __name__ == "__main__":
    print("--- Iniciando Simulação de Acordo de Chave com ECDH ---")

    # PASSO 1: Geração de Chaves ECC para Alice e Bob
    alice_private_key = ec.generate_private_key(ec.SECP256R1())
    alice_public_key = alice_private_key.public_key()

    bob_private_key = ec.generate_private_key(ec.SECP256R1())
    bob_public_key = bob_private_key.public_key()

    print("\n[SETUP] Alice e Bob geraram seus pares de chaves ECC.")

    # PASSO 2: Troca de Chaves Públicas (Simulação)
    print(
        "[REDE] Alice e Bob trocam suas chaves públicas através de um canal público..."
    )

    # PASSO 3: Acordo de Chave (A Mágica do ECDH)
    alice_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)
    print("\n[ALICE] Calculou um segredo compartilhado.")

    bob_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)
    print("[BOB] Calculou um segredo compartilhado.")

    # PASSO 4: Verificação Crucial
    if alice_shared_secret == bob_shared_secret:
        print("\n[VERIFICAÇÃO] O segredo de Alice e o de Bob são IDÊTICOS!")

    # PASSO 5: Derivação da Chave de Criptografia Final (KDF)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(alice_shared_secret)
    salsa20_key = digest.finalize()

    print(
        f"[KDF] Chave Salsa20 de 32 bytes derivada do segredo (hex): {salsa20_key.hex()}"
    )

    # PASSO 6: Usando a Chave Derivada para Comunicação Confidencial
    print("\n--- A comunicação segura começa agora usando a chave derivada ---")

    crypto_module = Salsa20Confidentiality(salsa20_key)

    mensagem_de_alice = "Bob, a chave foi trocada com sucesso. Podemos conversar."
    print(f"\n[ALICE] Mensagem Original: '{mensagem_de_alice}'")

    pacote_criptografado = crypto_module.encrypt(mensagem_de_alice)
    print(f"[ALICE] Pacote Criptografado (hex): {pacote_criptografado.hex()}")
    print(
        f"(Tamanho: {len(pacote_criptografado)} bytes = {Salsa20Confidentiality.NONCE_SIZE} de nonce + {len(pacote_criptografado) - Salsa20Confidentiality.NONCE_SIZE} de dados)"
    )

    print("\n... Pacote viaja pela rede ...\n")

    mensagem_recebida_por_bob = crypto_module.decrypt(pacote_criptografado)
    print(f"[BOB] Mensagem Descriptografada: '{mensagem_recebida_por_bob}'")

    if mensagem_de_alice == mensagem_recebida_por_bob:
        print(
            "✅ SUCESSO! A confidencialidade foi alcançada usando uma chave estabelecida dinamicamente via ECDH."
        )
