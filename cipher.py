import Crypto.Cipher.AES as AES
import Crypto.Protocol.KDF as kdf
import Crypto.Random as rand


def generate_key_from_password(password: str) -> tuple[bytes, bytes]:
    """Generate key from password"""
    salt: bytes = rand.get_random_bytes(16)
    return kdf.PBKDF2(password, salt, 16, 2_000_000), salt


def generate_key_from_password_with_salt(password: str, salt: bytes) -> bytes:
    """Generate key from password"""
    return kdf.PBKDF2(password, salt, 16, 2_000_000)


def encipher(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Encipher plaintext using AES-256-GCM"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, tag, ciphertext


def decipher(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    """Decipher ciphertext using AES-256-GCM"""
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
