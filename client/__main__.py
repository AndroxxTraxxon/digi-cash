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

def generateIdentities(identityString:str, quantity:int = 5, block_size:int = 32) -> tuple:
  
  def pad_bytes(s):
    bs = block_size
    return bytes(s + (bs - len(s) % bs) * chr(bs - len(s) % bs), 'utf-8')

  def unpad_bytes(s):
    return s[: -ord(s[len(s) - 1:])]

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
  token["uuid"] = uuid.uuid4().hex
  token["createdDate"] = datetime.datetime.now().isoformat()
  id_keys, token["identities"] = generateIdentities(identity)

  # pprint.pprint(token)
  token_json = json.dumps(token)
  checksum = hashlib.sha256(token_json.encode("utf-8")).hexdigest()
  # pprint.pprint(id_keys)
  return {
    "token": token,
    "checksum": checksum,
    "id_keys": id_keys,
    "merchant_pattern":None,
    "revealed_id": None
  }

tokens = dict()
for i in range(5):
  token = generateToken(1000, "Hello, World!")
  tokens[token["checksum"]] = token

pprint.pprint(tokens)

pprint.pprint([*tokens.keys()])
  


