
redeemed_tokens = dict()

class TokenAlreadyRedeemed(ValueError):
  pass

class MerchantDuplicateViolation(TokenAlreadyRedeemed):
  pass

class ClientDuplicateViolation(TokenAlreadyRedeemed):
  pass

def redeem_token(token:dict):
  token_id = token.get("token").get("uuid")
  if token_id in redeemed_tokens.keys():
    raise TokenAlreadyRedeemed