import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import json
import datetime
import os
from io import StringIO
import uuid
import pprint
import os
from blind_sig_util import modulo_multiplicative_inverse

import requests

_current_dir = os.path.dirname(os.path.realpath(__file__))
  

def generateIdentities(identityString:str, quantity:int = 5, block_size:int = 32) -> tuple:
  
  def pad_bytes(s):
    bs = block_size
    return bytes(s + (bs - len(s) % bs) * chr(bs - len(s) % bs), 'utf-8')

  def xor_bytes(a, b):
    return bytes(tuple(_a^ _b for _a, _b in zip(a, b)))

  keys, identities = [], []
  for i in range(quantity):
    _id_string = pad_bytes(("Identity %d:" % i) + identityString)
    otp = Random.get_random_bytes(len(_id_string))
    _id_string = xor_bytes(otp, _id_string)

    otp_checksum = hashlib.sha256(otp).hexdigest()
    otp_key, otp_iv = Random.get_random_bytes(16), Random.get_random_bytes(AES.block_size)
    otp_cipher = AES.new(otp_key, AES.MODE_CBC, otp_iv)
    otp_enc = base64.b64encode(otp_iv + otp_cipher.encrypt(otp)).decode("utf-8")

    id_checksum = hashlib.sha256(_id_string).hexdigest()
    id_key, id_iv = Random.get_random_bytes(16), Random.get_random_bytes(AES.block_size)
    id_cipher = AES.new(id_key, AES.MODE_CBC, id_iv)
    id_enc = base64.b64encode(id_iv + id_cipher.encrypt(_id_string)).decode("utf-8")
    keys.append((base64.b64encode(otp_key).decode('utf-8'), base64.b64encode(id_key).decode('utf-8')))
    identities.append({
      "identity": (otp_enc, id_enc),
      "checksum": (otp_checksum, id_checksum)
    })
  return keys, identities

def generateToken(amount: float, identity:str) -> dict:
  token = dict()
  token["amount"] = amount
  token["uuid"] = str(uuid.uuid4())
  token["created_datetime"] = datetime.datetime.now().isoformat()
  id_keys, token["identities"] = generateIdentities(identity)

  # pprint.pprint(token)
  token_json = json.dumps(token)
  checksum = hashlib.sha256(token_json.encode("utf-8")).hexdigest()
  # pprint.pprint(id_keys)
  return {
    "token": token,
    "checksum": checksum,
    "identity_keys": id_keys
  }


response = requests.get("http://localhost:5000/public-key")
data = response.json()
e = int.from_bytes(bytes.fromhex(data.get("key")), 'big')
n = int.from_bytes(bytes.fromhex(data.get("modulus")), 'big')
n_len = data.get("modulus_len")


# k = int.from_bytes(Random.get_random_bytes(128), 'big')
# k_inv = modulo_multiplicative_inverse(k, n)

# message = "Hello World"
# M = int.from_bytes(hashlib.sha256(message.encode('utf-8')).digest(), 'big')

# print(M)
# C = (M*pow(k, e, n)) % n
# print(C)
# Ch = C.to_bytes(len(data.get("modulus"))//2, 'big')
# print(Ch)


# generate tokens for request.

tokens = dict()
for i in range(5):
  token = generateToken(1000, "Hello, World!")
  k = int.from_bytes(Random.get_random_bytes(128), 'big')
  k_inv = modulo_multiplicative_inverse(k, n)
  token["key"] = k
  token["key-inverse"] = k_inv
  
  M = int.from_bytes(bytes.fromhex(token["checksum"]), 'big')
  C = (M*pow(k, e, n)) % n
  C = C.to_bytes(n_len, 'big').hex()

  tokens[C] = token
  # print(C, end="\n\n")

checksums = list(tokens.keys())
print(checksums)

# open request with bank
response = requests.post("http://localhost:5000/open-request", json=checksums)
data = response.json()
print("\nOpen request: \n" + str(data))

keep = data["keep"]
# send requested tokens
response = requests.post("http://localhost:5000/fill-request", json={
  "session_id": data.get("session_id"),
  "tokens": {key: value for key, value in tokens.items() if key != keep}
})
signature = None
try:
  data = response.json()
  print("\n Fill request: " + str(data))
  signature = int.from_bytes(bytes.fromhex(data.get("signature")), 'big')
except Exception as e:
  print(e)
  print("Fill request Failed: \n" + response.text)

print("\n%d" % signature)

# validate signature
token = tokens[keep]
checksum = int.from_bytes(bytes.fromhex(token["checksum"]), 'big')
t_inv = token["key-inverse"]

signature = (signature * t_inv) % n
_validation = pow(signature, e, n)

print(_validation)
print(checksum)

print(_validation == checksum)




  
