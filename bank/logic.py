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
from util import blind_signatures

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
  signature = int.from_bytes(bytes.fromhex(token.get("signature")), "big")
  checksum = int.from_bytes(bytes.fromhex(token.get("checksum")), "big")
  blind_signatures.validate_signature(checksum, signature, (get_public_key(), get_public_modulus()))
  return True

def verify_checksum(token:dict):
  blind_signatures.validate_checksum(json.dumps(token["token"]), bytes.fromhex(token["checksum"]))
  return True

def verify_revealed_identities(claim:dict):
  merchant_bitstring = claim["identity-pattern"]
  checksums = [identity["checksum"] for identity in claim["token"]["identities"]]
  revealed_identities = claim["revealed-identities"]
  for toggle, checksum, identity in zip(merchant_bitstring, checksums, revealed_identities):
    checksum = bytes.fromhex(checksum[toggle])
    identity = bytes.fromhex(identity)
    blind_signatures.validate_checksum(identity, checksum)
  return True

def redeem_token(claim:dict):
  verify_format(claim)
  verify_checksum(claim)
  verify_signature(claim)
  verify_revealed_identities(claim)
  existing_token = data.get_token(claim["token"]["uuid"])
  if(existing_token is not None):
    existing_bitstring = existing_token["identity-pattern"]
    new_bitstring = claim["identity-pattern"]
    if existing_bitstring == new_bitstring:
      raise MerchantSpentAgain()
    else:
      raise ClientSpentAgain()
  else:
    data.redeem_token(claim)
  return claim["checksum"]

def open_signing_request(tokens_to_validate):
  session_id = str(uuid.uuid4())
  keep = random.choice(tokens_to_validate)
  tokens_to_validate.remove(keep)
  _sessions[session_id] = tokens_to_validate, keep
  return keep, session_id

def fill_signing_request(session_id, claims):
  if session_id in _sessions:
    checksums, checksum_to_sign = _sessions[session_id]
    del _sessions[session_id]
    for checksum, claim in claims.items():
      if checksum not in checksums:
        raise ValueError("This token never appeared in the query: %s" % checksum)

      # do full validation of all the tokens
      verify_checksum(claim)      
      verify_format(claim)

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