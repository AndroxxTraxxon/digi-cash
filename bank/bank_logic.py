
from bank_data import redeem_token as data_redeem_token
from datetime import datetime
import json
import uuid
import base64
import os

class TokenFormatMalformed(ValueError):
  """ To be raised when the format file is not properly formed """
  pass

class BadTokenFormat(ValueError):
  """ To be raised when the provided token does not follow the defined token format. """
  pass

class BadSignature(ValueError):
  """ To be raised when the provided token's signature does not validated """
  pass

class TokenAlreadyRedeemed(ValueError):
  pass

_current_dir = os.path.dirname(os.path.realpath(__file__))

def _get_token_signature(token:dict):
  return 

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
      "int": int
    }

    def _bitstring_decode(value:str):
      output = list()
      for char in value:
        if value == "0":
          output.append(False)
        elif value == "1":
          output.append(True)
        else:
          raise ValueError("Expected 0 or 1, found %s" % char)
      return tuple(output)

    def _check_format_str(item, key, expected_type, parent=""):
      fullPath = (parent + "." + key) if parent else key
      _type = _expected_types.get(expected_type)
      if _type is None:
        raise TokenFormatMalformed("Unknown type for %s: %s" % (fullPath, value))
      if isinstance(item, expected_type):
        return True
      else:
        raise BadTokenFormat("Token has incorrect value for %s : %s; expected type %s"%(fullPath, item, expected_type))
    
    def _check_format_dict(item, key, expected_format, parent=""):
      fullPath = (parent + "." + key) if parent else key
      if(expected_format.get("type") is None):
        raise BadTokenFormat("Expected type for %s, found None" % fullPath)
      _type = _expected_types.get(expected_format["type"])
      if _type is None:
        raise BadTokenFormat("Unknown type for %s: %s" % (fullPath, value))
      if isinstance(item, _type):
        raise BadTokenFormat("Token has incorrect value for %s : %s; expected type %s"%(fullPath, item.__class__.__name, expected_format["type"]))
      
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
          _parser = {
            "uuid": uuid.UUID,
            "datetime": datetime.fromisoformat,
            "base-64": base64.b64decode,
            "bitstring": _bitstring_decode
          }.get(_expected_str_format)
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
          for i in item:
            _check_format(_expected_item_format, i, parent=fullPath)

    for key, value in _format.items():
      if isinstance(value, dict):
        if token.get(key) is None:
          raise BadTokenFormat("Expected value for %s, found None" % key)
        _check_format_dict(token[key], key, value)
      elif isinstance(value, str):
        if token.get(key) is None:
          raise BadTokenFormat("Expected value for %s, found None" % key)
        _check_format_str(token[key], key, value)
      else:
        raise TokenFormatMalformed("Unexpected value in token format")
  return True

def verify_signature(token:dict):
  signature = token.get("signature")
  if signature is None:
    raise BadSignature("Signature does not exist")
  if len(signature) == 256:
    return True
  else:
    raise BadSignature("Signature is not the correct length!")

def redeem_token(token:dict):
  verify_format(token)
  verify_signature(token)
  data_redeem_token(token)
  return token["checksum"]
