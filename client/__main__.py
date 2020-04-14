import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import requests
from util.blind_signatures import validate_signature, modulo_multiplicative_inverse
import pprint
import uuid
import datetime
import json
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
from util.encryption import aes_encrypt


_current_dir = os.path.dirname(os.path.realpath(__file__))


def generateIdentities(identityString: str, quantity: int = 5, block_size: int = 32) -> tuple:

    def pad_bytes(s):
        bs = block_size
        return bytes(s + (bs - len(s) % bs) * chr(bs - len(s) % bs), 'utf-8')

    def xor_bytes(a, b):
        return bytes(tuple(_a ^ _b for _a, _b in zip(a, b)))

    keys, identities = [], []
    for i in range(quantity):
        _id_string = pad_bytes(("Identity %d:" % i) + identityString)
        otp = Random.get_random_bytes(len(_id_string))
        _id_string = xor_bytes(otp, _id_string)

        otp_checksum = hashlib.sha256(otp).hexdigest()
        otp_key = Random.get_random_bytes(16)
        otp_enc = aes_encrypt(otp, otp_key).hex()

        id_checksum = hashlib.sha256(_id_string).hexdigest()
        id_key = Random.get_random_bytes(16)
        id_enc = aes_encrypt(_id_string, id_key).hex()
        keys.append((otp_key.hex(), id_key.hex()))
        identities.append({
            "identity": (otp_enc, id_enc),
            "checksum": (otp_checksum, id_checksum)
        })
    return keys, identities


def generateToken(amount: float, identity: str) -> dict:
    token = dict()
    token["amount"] = amount
    token["uuid"] = str(uuid.uuid4())
    token["created_datetime"] = datetime.datetime.now().isoformat()
    id_keys, token["identities"] = generateIdentities(identity)

    # pprint.pprint(token)
    token_json = json.dumps(token)
    checksum = hashlib.sha256(token_json.encode("utf-8")).hexdigest()
    # pprint.pprint(id_keys)
    return {
        "token": token,
        "checksum": checksum,
        "identity_keys": id_keys
    }


def orderToken():
    response = requests.get("http://localhost:5000/public-key")
    data = response.json()
    e = int.from_bytes(bytes.fromhex(data.get("key")), 'big')
    n = int.from_bytes(bytes.fromhex(data.get("modulus")), 'big')
    n_len = data.get("modulus_len")

    tokens = dict()
    for _ in range(5):
        token = generateToken(1000, "Hello, World!")
        k = int.from_bytes(Random.get_random_bytes(128), 'big')
        k_inv = modulo_multiplicative_inverse(k, n)
        token["key"] = k
        token["key-inverse"] = k_inv

        M = int.from_bytes(bytes.fromhex(token["checksum"]), 'big')
        C = (M*pow(k, e, n)) % n
        C = C.to_bytes(n_len, 'big').hex()

        tokens[C] = token
        # print(C, end="\n\n")

    checksums = list(tokens.keys())
    print("Generated tokens: ", *map(lambda x:"\n" + x[:16], checksums))

    # open request with bank
    response = requests.post(
        "http://localhost:5000/open-request", json=checksums)
    data = response.json()

    keep = data["keep"]
    print("Bank will sign: " + keep[:16])
    # send requested tokens
    response = requests.post("http://localhost:5000/fill-request", json={
        "session_id": data.get("session_id"),
        "tokens": {key: value for key, value in tokens.items() if key != keep}
    })
    signature = None
    try:
        data = response.json()
        signature = int.from_bytes(bytes.fromhex(data.get("signature")), 'big')
    except Exception as e:
        print(e)
        print("Fill request Failed: \n" + response.text)

    # validate signature
    token = tokens[keep]
    checksum = int.from_bytes(bytes.fromhex(token["checksum"]), 'big')
    t_inv = token["key-inverse"]

    signature = (signature * t_inv) % n
    validate_signature(checksum, signature, (e, n))
    token["signature"] = signature.to_bytes(n_len, 'big').hex()
    print("Bank signature: " + token["signature"][:16])
    token["bank-address"] = "http://localhost:5000"

    del token["key-inverse"]
    # remove these from the token as they are no longer necessary
    del token["key"]

    with open(os.path.join(_current_dir, "tokens", "token.json"), "w+") as token_output:
        json.dump(token, token_output)


def makePurchase():
    claim = None
    with open(os.path.join(_current_dir, "tokens", "token.json")) as token_output:
        claim = json.load(token_output)
    
    print("Sending token to purchase from merchant...")
    pprint.pprint(claim)
    purchase_token = { key: value for key, value in claim.items() if key != "identity_keys" }
    response = requests.post("http://localhost:5001/request-spend", json=purchase_token)
    print(response.text)
    data = response.json()
    session_id = data.get("session_id")

    keys = claim["identity_keys"]
    purchase_keys = [key[i] for key, i in zip(keys, data["bitstring"])]

    response = requests.post("http://localhost:5001/fill-request", json={
        "session_id": session_id,
        "keys": purchase_keys
    })
    print(response)


if __name__ == "__main__":
    try:
        command = sys.argv[1]
    except IndexError as e:
        command = "order"
    {
        "order": orderToken,
        "purchase": makePurchase
    }[command]()
