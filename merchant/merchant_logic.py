from Crypto.Random import random
from util.encryption import aes_decrypt
from util.blind_signatures import validate_checksum, validate_signature
import json
import uuid
import requests
import os
import sys
import traceback
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
_sessions = dict()


def redeem_token(claim):
    try:
        # verify the checksum of the file against its "token" object
        token = claim["token"]
        token_str = json.dumps(token)
        checksum = bytes.fromhex(claim["checksum"])
        validate_checksum(token_str, checksum)

        response = requests.get(claim["bank-address"] + "/public-key")
        data = response.json()
        e = int.from_bytes(bytes.fromhex(data.get("key")), "big")
        n = int.from_bytes(bytes.fromhex(data.get("modulus")), "big")

        checksum = int.from_bytes(checksum, "big")
        signature = int.from_bytes(
            bytes.fromhex(claim.get("signature")), "big")
        validate_signature(checksum, signature, (e, n))

        session_id = str(uuid.uuid4())
        pattern = list(random.choice([0, 1])
                       for identity in token["identities"])
        _sessions[session_id] = claim, pattern
        return session_id, pattern
    except Exception as e:
        traceback.print_exc()
        raise e


def fill_request(session_id, keys):
    try:
        claim, pattern = _sessions[session_id]
        identities = claim["token"]["identities"]
        decrypted_identities = []
        for index, (key, id_obj, toggle) in enumerate(zip(keys, identities, pattern)):
            print(index, key, id_obj, toggle)
            enc_identity = bytes.fromhex(id_obj["identity"][toggle])
            key = bytes.fromhex(key)
            print(key, enc_identity)
            dec_identity = aes_decrypt(enc_identity, key)
            checksum = bytes.fromhex(id_obj["checksum"][toggle])
            validate_checksum(dec_identity, checksum, verbose=True)
            print("Validated %d" % index)
            decrypted_identities.append(dec_identity.hex())
        claim["revealed-identities"] = decrypted_identities
        claim["identity-pattern"] = pattern

        response = requests.post(claim["bank-address"] + "/redeem", json=claim)
        print(response.text)
    except Exception as e:
        print(e.__class__.__name__)
        print(e)
        traceback.print_exc()
        raise e
    return True
