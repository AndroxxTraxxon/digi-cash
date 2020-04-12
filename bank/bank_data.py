from blind_sig_util import generate_keychain

redeemed_tokens = dict()

_e, _d, _n = generate_keychain()

def redeem_token(token:dict):
  token_id = token.get("token").get("uuid")
  redeemed_tokens[str(token_id)] = token
  return token_id

def get_token(token_id:str):
  return redeemed_tokens.get(str(token_id))

def get_public_key():
  return _e

def get_private_key():
  return _d

def get_public_modulus():
  return _n