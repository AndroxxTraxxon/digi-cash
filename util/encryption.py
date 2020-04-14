from Crypto.Cipher import AES
from Crypto import Random


def _pad(s:bytes) -> bytes:
    bs = AES.block_size * 2
    return s + bytes((bs - len(s) % bs) * chr(bs - len(s) % bs), 'utf-8')

def _unpad(s:bytes) -> bytes:
    return s[: -ord(s[len(s) - 1:])]

def aes_encrypt(raw: bytes, key:bytes) -> bytes:
    raw = _pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(raw)
def aes_decrypt(enc: bytes, key:bytes) -> bytes:
    iv = enc[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _unpad(
        cipher.decrypt(
            enc[AES.block_size:]
            )
        )