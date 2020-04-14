import sys, os, datetime, json, uuid

_token_format = None
_current_dir = os.path.dirname(os.path.realpath(__file__))
sys.argv.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from util.custom_exceptions import BadTokenFormat, TokenFormatMalformed

def _bitstring_decode(value:str):
  output = list()
  for char in value:
    if char in "01":
      output.append(int(char))
    else:
      raise ValueError("Expected 0 or 1, found %s" % char)
  return tuple(output)

def get_token_format():
  global _token_format
  if _token_format is None:
    with open(os.path.join(_current_dir, "token_format.json")) as tf_file:
      _token_format = json.load(tf_file)
  return _token_format

def verify_format(token:dict):
  token_format = get_token_format()
  
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
            raise TokenFormatMalformed("Enum options not defined for %s"% fullPath)
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
              _check_format_dict(i, _expected_item_format, index, parent=fullPath + "[%d]"%index)
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
          _check_format_str(token[key], key, value)
        else:
          raise TokenFormatMalformed("Unexpected value in token format")
  
  _check_format(token_format, token)
  return True