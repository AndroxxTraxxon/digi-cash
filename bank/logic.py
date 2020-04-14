import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import bank.data as data
import datetime
import json
import uuid
import hashlib
import rsa
import random
from Crypto.Cipher import AES
from util.token_format import (
  verify_format, #        function: Token format verification
  _bitstring_decode, #    function: turns binary strings into int lists: "010101" -> [0, 1, 0, 1, 0, 1]
  BadTokenFormat, #       Exception: Raised when poorly formatted token is provided
  TokenFormatMalformed #  Exception: Raised when token format file is malformed
)
from util.custom_exceptions import BadSignature, ChecksumConflict

class TokenAlreadyRedeemed(ValueError):
  """ To be raised when a token is provided for redemption a second time. """
  pass

class MerchantSpentAgain(TokenAlreadyRedeemed):
  """ To be raised when a merchant is detected redeeming a token again. """
  pass

class ClientSpentAgain(TokenAlreadyRedeemed):
  """ To be raised when a client is detected redeeming a token again. """
  pass

class InvalidSession(ValueError):
  """ To be raised when an unknown or expired session id is provided. """
  pass

class MissingToken(ValueError):
  """ To be raised when validating collection of tokens not signed by the bank, and a token is missing"""
  pass

_sessions = dict()

def verify_signature(token:dict):
  signature = token.get("signature")
  checksum = token.get("checksum")
  if signature is None:
    raise BadSignature("Signature does not exist")

def verify_checksum(token:dict):
  reported_checksum = token.get("checksum")
  # if this fails for valid tokens, use OrderedDict to fix the order of the dictionaries. (Necessary for python <= 3.6)
  if reported_checksum is None:
    raise BadTokenFormat("There is no checksum")
  if reported_checksum != hashlib.sha256(json.dumps(token["token"]).encode("utf-8")).hexdigest():
    raise ChecksumConflict("Token does not match its checksum!")
  return True

def verify_revealed_identities(token:dict):
  def unpad_bytes(s):
    return s[: -ord(s[len(s) - 1:])]

  def _decrypt_padded(ciphertext, key):
    enc = bytes.fromhex(ciphertext)
    iv = enc[: AES.block_size]
    key = bytes.fromhex(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
      return unpad_bytes(
        cipher.decrypt(
          enc[AES.block_size:]
        )
      ).decode("utf-8")
    except UnicodeDecodeError:
      raise ValueError("Unable to decrypt ciphertext.")


  merchant_bitstring = token["identity-pattern"]
  print(merchant_bitstring)
  identities = token["token"]["identities"]
  keys = token["identity_keys"]
  for index, (b, (i, c), k) in enumerate(zip(merchant_bitstring, identities, keys)):
    i,c, k = i[b], c[b], k[b]
    if hashlib.sha256(i.encode("utf-8")).hexdigest() != c:
      raise ChecksumConflict("Identity at index %d does not generate its checksum!" % index)
  return True

def redeem_token(token:dict):
  verify_format(token)
  verify_checksum(token)
  # verify_signature(token)
  # verify_revealed_identities(token)
  existing_token = data.get_token(token["token"]["uuid"])
  if(existing_token is not None):
    existing_bitstring = existing_token["identity-pattern"]
    new_bitstring = token["identity-pattern"]
    if existing_bitstring == new_bitstring:
      raise MerchantSpentAgain()
    else:
      raise ClientSpentAgain()
  else:
    data.redeem_token(token)
  return token["checksum"]

def open_signing_request(tokens_to_validate):
  session_id = str(uuid.uuid4())
  keep = random.choice(tokens_to_validate)
  tokens_to_validate.remove(keep)
  _sessions[session_id] = tokens_to_validate, keep
  return keep, session_id

def fill_signing_request(session_id, tokens):
  if session_id in _sessions:
    checksums, checksum_to_sign = _sessions[session_id]
    del _sessions[session_id]
    for checksum, token in tokens.items():
      if checksum not in checksums:
        raise ValueError("This token never appeared in the query: %s" % checksum)
      # do full validation of all the tokens

    d = data.get_private_key()
    n = data.get_public_modulus()

    t = int.from_bytes(bytes.fromhex(checksum_to_sign), 'big')
    return pow(t, d, n).to_bytes(256, 'big').hex()

  else:
    raise InvalidSession("Invalid session token")

def get_public_key():
  return data.get_public_key()

def get_public_modulus():
  return data.get_public_modulus()