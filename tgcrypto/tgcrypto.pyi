def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES256-IGE Encryption"""
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES256-IGE Decryption"""
def ctr256_encrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes:
    """AES256-CTR Encryption"""
def ctr256_decrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes:
    """AES256-CTR Decryption"""
def cbc256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES256-CBC Encryption"""
def cbc256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES256-CBC Decryption"""
