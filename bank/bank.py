from flask import Flask, jsonify, request, Response, abort
import werkzeug.exceptions as w_ex

from bank_logic import verify_format, BadTokenFormat

web = Flask("digi-cash-bank")

spent_tokens = dict()

@web.errorhandler(400)
def malformed_request(e):
  return jsonify({
    "status": "Error 400: Malformed request.",
    "message": e
  }), 400

@web.errorhandler(404)
def resource_not_found(e):
  return jsonify({
    "status": "Error 404: Endpoint not found.",
    "message": e
  }), 404


@web.route("/redeem", methods=["POST"])
def redeem_token():
  if(request.is_json()):
    token = request.json
    try:
      verify_format(token)
    except BadTokenFormat as e:
      abort(400, "Token does not have the correct format!")
  else:
    abort(400, "Token must be in JSON format!")

@web.route("/", methods=["GET"])
def hello_world():
  return "Hello, World!", 200


web.run()