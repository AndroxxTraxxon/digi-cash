import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
import bank.logic as logic
from flask import Flask, jsonify, request, Response, abort


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


@web.errorhandler(500)
def unknown_error(e):
    return jsonify({
        "status": "Unknown Error",
        "message": str(e),
    }), 500


@web.route("/redeem", methods=["POST"])
def redeem_token():
    if request.is_json:
        token = request.json
        try:
            return jsonify({
                "token": logic.redeem_token(token),
                "status": "success"
            })

        except logic.BadTokenFormat:
            return jsonify({
                "status": "rejected",
                "message": "This token has an incorrect format",
            }), 400
        except logic.BadSignature:
            return jsonify({
                "status": "rejected",
                "message": "The bank signature on this token does not match.",
            }), 403
        except logic.ChecksumConflict:
            return jsonify({
                "status": "rejected",
                "message": "The checksum does not match the token content.",
            }), 400
        except logic.MerchantSpentAgain:
            return jsonify({
                "status": "rejected",
                "message": "The merchant has already redeemed this token.",
            }), 403
        except logic.ClientSpentAgain:
            return jsonify({
                "status": "rejected",
                "message": "The client has already redeemed this token.",
            }), 403

    else:
        return jsonify({
            "status": "rejected",
            "message": "Token must be in JSON format.",
        }), 400


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
            return jsonify({
                "status": "rejected",
                "message": "Unknown Error",
                "error": str(e)
            }), 500

    else:
        return jsonify({
            "status": "rejected",
            "message": "Token must be in JSON format.",
        }), 400


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
        except logic.TokenValueMismatch as e:
            return jsonify({
                "status": "rejected",
                "message": "Token mismatch",
                "error": str(e)
            }), 403
        except Exception as e:
            return jsonify({
                "status": "rejected",
                "message": "Unknown Error",
                "error": str(e)
            }), 500

    else:
        return jsonify({
            "status": "rejected",
            "message": "Token must be in JSON format.",
        }), 400


@web.route("/public-key", methods=["GET"])
def public_key():
    try:
        return jsonify({
            "key": logic.get_public_key().to_bytes(128, 'big').hex(),  # generated 128-byte number
            "key_len": 128,
            # product of 2 128-byte numbers
            "modulus": logic.get_public_modulus().to_bytes(256, 'big').hex(),
            "modulus_len": 256,
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "status": "rejected",
            "message": "Unknown Error",
            "error": str(e),
        }), 500


@web.route("/", methods=["GET"])
def hello_world():
    return "Hello, World!", 200


if __name__ == "__main__":
    web.run(port=5000, debug=True)
