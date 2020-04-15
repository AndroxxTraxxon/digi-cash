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

_current_dir = os.path.dirname(os.path.realpath(__file__))


class TokenRejected(ValueError):
    pass


def redeem_token(claim):
    try:
        # verify the checksum of the file against its "token" object
        token = claim["token"]
        token_str = json.dumps(token)
        print("Verifying token...")
        checksum = bytes.fromhex(claim["checksum"])
        validate_checksum(token_str, checksum)
        print("Validated Checksum.")
        print("Fetching Keys from Bank")
        response = requests.get(claim["bank-address"] + "/public-key")
        data = response.json()
        e = int.from_bytes(bytes.fromhex(data.get("key")), "big")
        n = int.from_bytes(bytes.fromhex(data.get("modulus")), "big")
        print("Validating Bank Signature...")
        checksum = int.from_bytes(checksum, "big")
        signature = int.from_bytes(
            bytes.fromhex(claim.get("signature")), "big")
        validate_signature(checksum, signature, (e, n))
        print("Signature Good.")

        session_id = str(uuid.uuid4())
        print("Establishing Session: %s" % session_id)
        pattern = list(random.choice([0, 1])
                       for identity in token["identities"])
        print("Requesting keys for from Client: \n" + str(pattern))
        _sessions[session_id] = claim, pattern
        return session_id, pattern
    except Exception as e:
        raise e


def fill_request(session_id, keys, malicious=False):
    try:
        claim, pattern = _sessions[session_id]
        del _sessions[session_id]
        identities = claim["token"]["identities"]
        decrypted_identities = []
        for index, (key, id_obj, toggle) in enumerate(zip(keys, identities, pattern)):
            print("Decrypting %s half of identity %d..." % (("left", "right")[toggle], index))
            enc_identity = bytes.fromhex(id_obj["identity"][toggle])
            key = bytes.fromhex(key)
            # print(key, enc_identity)
            dec_identity = aes_decrypt(enc_identity, key)
            print("Validating decrypted identity part...")
            checksum = bytes.fromhex(id_obj["checksum"][toggle])
            validate_checksum(dec_identity, checksum)
            # print("Validated %d" % index)
            print("Identity %d is valid." % index)
            decrypted_identities.append(dec_identity.hex())
        claim["revealed-identities"] = decrypted_identities
        claim["identity-pattern"] = pattern
        with open(os.path.join(_current_dir, "tokens", "revealed_token.json"), "w+") as token_output:
            json.dump(claim, token_output, indent=4)
        response = requests.post(claim["bank-address"] + "/redeem", json=claim)
        print(response.text)
        if malicious:
            # try to redeem again
            response = requests.post(claim["bank-address"] + "/redeem", json=claim)
            print("Second response: \n%s" % response.text)
        
        if not response.ok:
            raise TokenRejected(response.json()["message"])

    except Exception as e:
        print(e.__class__.__name__)
        print(e)
        raise e
    return True
