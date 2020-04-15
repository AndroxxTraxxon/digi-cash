import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from flask import Flask, jsonify, request, Response, abort
import merchant.merchant_logic as logic
from util.custom_exceptions import BadSignature, BadTokenFormat
# from util.blind_signatures import
web = Flask('digi-cash-merchant')


@web.errorhandler(500)
def unknown_error(e):
    print(type(e).__name__)
    return jsonify({
        "status": "Unknown Error",
        "message": str(e),
    }), 500

@web.route("/request-spend", methods=["POST"])
def spend_token():
    if request.is_json:
        token = request.json
        try:
            session_id, pattern = logic.redeem_token(token)
            return jsonify({
                "session_id": session_id,
                "bitstring": pattern,
                "status": "accepted"
            })
        except BadSignature as e :
            return jsonify({
                "message": "Bank Signature Does not match, you cheater!",
                "status": "rejected"
            }), 403
        except BadTokenFormat as e:
            return jsonify({
                "message": "Token has incorrect format",
                "status": "rejected"
            }), 400
        except logic.TokenRejected as e:
            return jsonify({
                "message": "The claim was rejected by the bank.",
                "status": "rejected",
                "error": str(e)
            }), 403
        except Exception as e:
            return jsonify({
                "message": "Unknown Error",
                "status": "rejected",
                "error": str(e)
            }), 500
    else:
        return jsonify({
            "message": "Must be in JSON format",
            "status": "rejected"
        }), 400


@web.route("/fill-request", methods=["POST"])
def fill_request():
    if request.is_json:
        data = request.json
        session_id = data["session_id"]
        keys = data["keys"]
        try:
            logic.fill_request(session_id, keys)
        except Exception as e:
            print("Unknown error: " + str(e))
            abort(500, "Unknown error: " + str(e))
    return "something", 200

@web.route("/fill-request-malicious", methods=["POST"])
def fill_request_malicious():
    if request.is_json:
        data = request.json
        session_id = data["session_id"]
        keys = data["keys"]
        try:
            logic.fill_request(session_id, keys, malicious=True)
        except logic.TokenRejected as e:
            return jsonify({
                "message": "The claim was rejected by the bank.",
                "status": "rejected",
                "error": str(e)
            }), 403
        except Exception as e:
            print("Unknown error: " + str(e))
            abort(500, "Unknown error: " + str(e))
    return "something", 200


if __name__ == "__main__":
    web.run(port=5001, debug=True)
