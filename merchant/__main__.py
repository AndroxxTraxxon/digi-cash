import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
import merchant.merchant_logic as logic
from flask import Flask, jsonify, request, Response, abort
# from util.blind_signatures import
web = Flask('digi-cash-merchant')


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
        except Exception as e:
            abort(500, "Unknown error: " + type(e).__name__ + ": " + str(e))
    else:
        abort(400, "Must be in JSON format!")


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


if __name__ == "__main__":
    web.run(port=5001, debug=True)
