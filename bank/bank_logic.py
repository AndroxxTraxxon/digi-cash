
import bank_data
import datetime
import json
import uuid
import base64
import os
import hashlib
from Crypto.Cipher import AES

class TokenFormatMalformed(ValueError):
  """ To be raised when the format file is not properly formed """
  pass

class BadTokenFormat(ValueError):
  """ To be raised when the provided token does not follow the defined token format. """
  pass

class BadSignature(ValueError):
  """ To be raised when the provided token's signature does not validated """
  pass

class ChecksumConflict(ValueError):
  """ To be raised when validating checksums, and they don't match. """

class TokenAlreadyRedeemed(ValueError):
  pass

class MerchantSpentAgain(TokenAlreadyRedeemed):
  pass

class ClientSpentAgain(TokenAlreadyRedeemed):
  pass

_current_dir = os.path.dirname(os.path.realpath(__file__))

def _bitstring_decode(value:str):
  output = list()
  for char in value:
    if char in "01":
      output.append(int(char))
    else:
      raise ValueError("Expected 0 or 1, found %s" % char)
  return tuple(output)

def verify_format(token:dict):
  token_format = None
  with open(os.path.join(_current_dir, "token_format.json")) as tf_file:
    token_format = json.load(tf_file)
  
  def _check_format(_format, token, parent = ""):
    _expected_types = {
      "str" : str,
      "list" : list,
      "dict" : dict,
      "float" : float,
      "int": int, 
    }

    _string_formats = {
      "uuid" : uuid.UUID,
      "datetime" : datetime.datetime.fromisoformat,
      "date" : datetime.date.fromisoformat,
      "base-64" : base64.b64decode,
      "bitstring" : _bitstring_decode,
      "hex" : bytes.fromhex,
    }

    def _check_format_str(item, key:str, expected_type:str):
      fullPath = (parent + "." + key) if parent else key
      _type = _expected_types.get(expected_type)
      if _type is None:
        raise TokenFormatMalformed("Unknown type for %s: %s" % (fullPath, str(item)))
      if isinstance(item, _type):
        return True
      else:
        raise BadTokenFormat("Token has incorrect value for %s : %s; expected type %s"%(fullPath, item, expected_type))
    
    def _check_format_dict(item, key:str, expected_format:dict, parent:str=""):
      fullPath = (parent + "." + key) if parent else key
      if(expected_format.get("type") is None):
        raise BadTokenFormat("Expected type for %s, found None" % fullPath)
      _type = _expected_types.get(expected_format["type"])
      if _type is None:
        if expected_format["type"] == "enum":
          if not isinstance(expected_format.get("options"), list):
            raise TokenFormatMalformed("Enum options not defined for %"% fullPath)
        raise BadTokenFormat("Unknown type for %s: %s" % (fullPath, str(item)))
      if not isinstance(item, _type):
        raise BadTokenFormat("Token has incorrect value for %s : %s; expected type %s"%(fullPath, item.__class__.__name__, expected_format["type"]))
      
      if _type is str:
        _expected_length = expected_format.get("length")
        if _expected_length is not None:
          if isinstance(_expected_length, int):
            if(_expected_length != len(item)):
              raise BadTokenFormat
          else:
            raise TokenFormatMalformed("(optional) Expected integer length for %s; found %s" % (fullPath, str(_expected_length)))
        _expected_str_format = expected_format.get("format")
        if _expected_str_format is not None:
          _parser = _string_formats.get(_expected_str_format)
          try:
            _tmp = _parser(item)
          except:
            raise BadTokenFormat("(optional) Expected format %s, found %s" % (_expected_str_format, item))
      
      if _type is dict:
        _expected_properties = expected_format.get("properties")
        if _expected_properties is None:
          raise TokenFormatMalformed("Expected dict properties for %s" % fullPath)
        else:
          _check_format(_expected_properties, item, parent=fullPath)
      if _type is list:
        _expected_length = expected_format.get("length")
        if _expected_length is not None:
          if isinstance(_expected_length, int):
            if(_expected_length != len(item)):
              raise BadTokenFormat("Expected %s to have length %d; found length %d" % (fullPath, _expected_length, len(item)))
          else:
            raise TokenFormatMalformed("(optional) Expected integer length for %s; found %s" % (key, str(_expected_length)))
        _expected_item_format = expected_format.get("format")
        if _expected_item_format is not None:
          for index, i in enumerate(item):
            if isinstance(_expected_item_format, str):
              _check_format_str(i, fullPath + "[%d]"%index, _expected_item_format)
            elif isinstance(_expected_item_format, dict):
              _check_format_dict(_expected_item_format, i, parent=fullPath + "[%d]"%index)
            else:
              raise TokenFormatMalformed("Unexpected format for %s"%fullPath)

      for key, value in _format.items():
        if isinstance(value, dict):
          if token.get(key) is None:
            raise BadTokenFormat("Expected value for %s, found None" % key)
          _check_format_dict(token[key], key, value, parent=parent)
        elif isinstance(value, str):
          print(token, _format)
          if token.get(key) is None:
            raise BadTokenFormat("Expected value for %s, found None" % key)
          _check_format_str(token[key], key, value, parent=parent)
        else:
          raise TokenFormatMalformed("Unexpected value in token format")
  
  _check_format(token_format, token)
  return True

def verify_signature(token:dict):
  signature = token.get("signature")
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
    enc = base64.b64decode(ciphertext)
    iv = enc[: AES.block_size]
    key = base64.b64decode(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
      return unpad_bytes(
        cipher.decrypt(
          enc[AES.block_size:]
        )
      ).decode("utf-8")
    except UnicodeDecodeError:
      raise ValueError("Unable to decrypt ciphertext.")


  merchant_bitstring = _bitstring_decode(token["merchant_bitstring"])
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
  existing_token = bank_data.get_token(token["token"]["uuid"])
  if(existing_token is not None):
    existing_bitstring = existing_token["merchant_bitstring"]
    new_bitstring = token["merchant_bitstring"]
    if existing_bitstring == new_bitstring:
      raise MerchantSpentAgain()
    else:
      raise ClientSpentAgain()
  else:
    bank_data.redeem_token(token)
  return token["checksum"]
