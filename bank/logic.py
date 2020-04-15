import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from util.encryption import xor_bytes, _unpad, aes_decrypt
from util import blind_signatures
from util.custom_exceptions import BadSignature, ChecksumConflict
from util.token_format import (
    verify_format,  # function: Token format verification
    # function: turns binary strings into int lists: "010101" -> [0, 1, 0, 1, 0, 1]
    _bitstring_decode,
    BadTokenFormat,  # Exception: Raised when poorly formatted token is provided
    TokenFormatMalformed  # Exception: Raised when token format file is malformed
)
from Crypto.Cipher import AES
import random
import rsa
import hashlib
import uuid
import json
import datetime
import bank.data as data


class TokenValueMismatch(ValueError):
    """ To be raised when NOT all of the tokens that the client provides in a session match each other."""
    pass


class TokenAlreadyRedeemed(ValueError):
    """ To be raised when a token is provided for redemption a second time. """
    pass


class MerchantSpentAgain(TokenAlreadyRedeemed):
    """ To be raised when a merchant is detected redeeming a token again. """
    pass


class ClientSpentAgain(TokenAlreadyRedeemed):
    """ To be raised when a client is detected redeeming a token again. """
    pass


class InvalidSession(ValueError):
    """ To be raised when an unknown or expired session id is provided. """
    pass


class MissingToken(ValueError):
    """ To be raised when validating collection of tokens not signed by the bank, and a token is missing"""
    pass


_sessions = dict()


def verify_signature(token: dict):
    signature = int.from_bytes(bytes.fromhex(token.get("signature")), "big")
    checksum = int.from_bytes(bytes.fromhex(token.get("checksum")), "big")
    blind_signatures.validate_signature(
        checksum, signature, (get_public_key(), get_public_modulus()))
    return True


def verify_checksum(token: dict):
    blind_signatures.validate_checksum(json.dumps(
        token["token"]), bytes.fromhex(token["checksum"]))
    return True


def verify_revealed_identities(claim: dict):
    merchant_bitstring = claim["identity-pattern"]
    checksums = [identity["checksum"]
                 for identity in claim["token"]["identities"]]
    revealed_identities = claim["revealed-identities"]
    for toggle, checksum, identity in zip(merchant_bitstring, checksums, revealed_identities):
        checksum = bytes.fromhex(checksum[toggle])
        identity = bytes.fromhex(identity)
        blind_signatures.validate_checksum(identity, checksum)
    return True


def verify_all_identities(claim: dict):
    revealed_identity = None
    for keys, identities in zip(claim["identity_keys"], claim["token"]["identities"]):
        key_l, key_r = map(bytes.fromhex, keys)
        id_l, id_r = map(bytes.fromhex, identities["identity"])
        sum_l, sum_r = map(bytes.fromhex, identities["checksum"])
        id_l = aes_decrypt(id_l, key_l)
        blind_signatures.validate_checksum(id_l, sum_l)
        id_r = aes_decrypt(id_r, key_r)
        blind_signatures.validate_checksum(id_r, sum_r)
        full_id = _unpad(xor_bytes(id_l, id_r)).decode('utf-8')
        full_id = full_id.split(":", 1)[1].strip()
        if revealed_identity and full_id != revealed_identity:
            print("The identity strings on this token do not match:")
            print(full_id)
            print(revealed_identity)
            raise TokenValueMismatch("The identity strings on this token do not match: %s  ||| %s " % (full_id, revealed_identity))
        revealed_identity = full_id
    return revealed_identity

def redeem_token(claim: dict):
    verify_format(claim)
    verify_checksum(claim)
    verify_signature(claim)
    verify_revealed_identities(claim)
    existing_token = data.get_token(claim["token"]["uuid"])
    if(existing_token is not None):
        existing_bitstring = existing_token["identity-pattern"]
        new_bitstring = claim["identity-pattern"]
        if existing_bitstring == new_bitstring:
            print("The merchant tried to spend again!")
            raise MerchantSpentAgain()
        else:
            identity = None
            for a, b in zip(existing_token["revealed-identities"], claim["revealed-identities"]):
                if a != b:
                    identity = _unpad(xor_bytes(bytes.fromhex(
                        a), bytes.fromhex(b))).decode('utf-8').split(":", 1)[1].strip()
                    print(identity, "is trying to defraud the bank!")
            raise ClientSpentAgain("'%s' is trying to defraud the bank!" % identity)
    else:
        data.redeem_token(claim)
    return claim["checksum"]


def open_signing_request(tokens_to_validate):
    session_id = str(uuid.uuid4())
    keep = random.choice(tokens_to_validate)
    tokens_to_validate.remove(keep)
    _sessions[session_id] = tokens_to_validate, keep
    return keep, session_id


def fill_signing_request(session_id, claims):
    if session_id in _sessions:
        checksums, checksum_to_sign = _sessions[session_id]
        del _sessions[session_id]
        last_claim_value = None
        last_identity = None
        for checksum, claim in claims.items():
            if checksum not in checksums:
                error = "This token never appeared in the query: %s" % checksum
                print(error)
                raise ValueError(error)

            # do full validation of all the tokens
            verify_checksum(claim)
            verify_format(claim)
            identity = verify_all_identities(claim)
            if last_identity and identity != last_identity:
                print("The identities do not match on these tokens!")
                print(identity)
                print(last_identity)
                raise TokenValueMismatch("The identities do not match on these tokens: %s ||| %s" % (identity, last_identity))
            last_identity = identity
            if last_claim_value is not None and last_claim_value != claim["token"]["amount"]:
                print("The monetary values do not match on these tokens: %02f ||| %02f" % (last_claim_value, claim["token"]["amount"]))
                raise TokenValueMismatch("The monetary values do not match on these tokens: %02f ||| %02f" % (last_claim_value, claim["token"]["amount"]))
            last_claim_value = claim["token"]["amount"]

        d = data.get_private_key()
        n = data.get_public_modulus()

        t = int.from_bytes(bytes.fromhex(checksum_to_sign), 'big')
        return pow(t, d, n).to_bytes(256, 'big').hex()

    else:
        raise InvalidSession("Invalid session token")


def get_public_key():
    return data.get_public_key()


def get_public_modulus():
    return data.get_public_modulus()
