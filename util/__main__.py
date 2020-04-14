import sys, os
from Crypto import Random
from Crypto.Cipher import AES
_current_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.argv.append(_current_dir)

from encryption import aes_decrypt, aes_encrypt

key = Random.get_random_bytes(AES.block_size)

print(aes_decrypt(aes_encrypt("Hello, World!".encode("utf-8"), key), key))