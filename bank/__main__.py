import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from flask import Flask, jsonify, request, Response, abort
import bank.logic as logic


web = Flask("digi-cash-bank")

spent_tokens = dict()

@web.errorhandler(400)
def malformed_request(e):
  return jsonify({
    "status": "Error 400: Malformed request.",
    "message": str(e)
  }), 400

@web.errorhandler(404)
def resource_not_found(e):
  return jsonify({
    "status": "Error 404: Endpoint not found.",
    "message": str(e)
  }), 404


@web.route("/redeem", methods=["POST"])
def redeem_token():
  if request.is_json:
    token = request.json
    try:
      return jsonify({
        "token" : logic.redeem_token(token),
        "status" : "success"
      })
    except logic.BadTokenFormat as e:
      abort(400, str(e))
    except logic.BadSignature as e:
      abort(400, "The signature on this token is incorrect.")
    except logic.ChecksumConflict as e:
      abort(400, str(e))
    except logic.MerchantSpentAgain as e:
      abort(403, "The merchant has attempted to redeem again.")
    except logic.ClientSpentAgain as e:
      abort(403, "The client has attempted to redeem again.")
    except Exception as e:
      abort(500, "Unknown error: " + str(e))

  else:
    abort(400, "Message must be in JSON format!")


@web.route("/open-request", methods=["POST"])
def open_signing_request():
  if request.is_json:
    checksums = request.json
    try:
      keep, session_id = logic.open_signing_request(checksums)
      return jsonify({
        "keep": keep,
        "session_id": session_id,
        "status": "success"
      })
    except Exception as e:
      abort(500, "Unknown error: " + str(e))
      
  else:
    abort(400, "Message must be in JSON format!")

@web.route("/fill-request", methods=["POST"])
def fill_signing_request():
  """
  Expected request format:

  {
    "session_id": <session id>,
    "tokens": {
      <token 1 checksum> : {
        "key": <full key 1>, 
        "token": <full token 1>
      },
      <token 2 checksum> : [<full token 2>,
      ...
    }
  }
  """
  if request.is_json:
    try:
      tokens_to_validate = request.json.get("tokens")
      session_id = request.json.get("session_id")
      return jsonify({
        "signature": logic.fill_signing_request(session_id, tokens_to_validate),
        "status": "success"
      })
    except Exception as e:
      abort(500, "Unknown error: " + str(e))

  else:
    abort(400, "Message must be in JSON format!")

@web.route("/public-key", methods=["GET"])
def public_key():
  try:
    return jsonify({
      "key": logic.get_public_key().to_bytes(128, 'big').hex(), # generated 128-byte number
      "key_len": 128,
      "modulus": logic.get_public_modulus().to_bytes(256, 'big').hex(), # product of 2 128-byte numbers
      "modulus_len": 256,
      "status": "success"
    })
  except Exception as e:
    abort(500, "Unknown error: " + str(e))

    


@web.route("/", methods=["GET"])
def hello_world():
  return "Hello, World!", 200

if __name__ == "__main__":
  web.run(port=5000, debug = True)