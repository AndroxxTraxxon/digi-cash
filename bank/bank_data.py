
redeemed_tokens = dict()

def redeem_token(token:dict):
  token_id = token.get("token").get("uuid")
  redeemed_tokens[str(token_id)] = token
  return token_id

def get_token(token_id:str):
  return redeemed_tokens.get(str(token_id))

