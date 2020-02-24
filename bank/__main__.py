from flask import Flask, jsonify, request, Response, abort
import werkzeug.exceptions as w_ex


import bank_logic

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
        "token" : bank_logic.redeem_token(token),
        "status" : "success"
      })
    except bank_logic.BadTokenFormat as e:
      abort(400, str(e))
    except bank_logic.BadSignature as e:
      abort(400, "The signature on this token is incorrect.")
    except bank_logic.ChecksumConflict as e:
      abort(400, str(e))
    except bank_logic.MerchantSpentAgain as e:
      abort(403, "The merchant has attempted to redeem again.")
    except bank_logic.ClientSpentAgain as e:
      abort(403, "The client has attempted to redeem again.")
  else:
    abort(400, "Token must be in JSON format!")

@web.route("/", methods=["GET"])
def hello_world():
  return "Hello, World!", 200

if __name__ == "__main__":
  web.run()