# reference:  https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

import rsa


#  reference: https://www.youtube.com/watch?v=8e7MH78PhLU
def gen_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    with open('public_key', 'wb') as f:
        f.write(public_key.save_pkcs1('PEM'))
    with open('private_key', 'wb') as f:
        f.write(private_key.save_pkcs1('PEM'))

def file_open(file):
    key_file = open(file, 'rb')
    key_data = key_file.read()
    key_file.close()
    return key_data

def create_signature(FTE):
    private = rsa.PrivateKey.load_pkcs1(file_open('private_key'))

    bank_note = file_open(FTE)
    # hash_value = rsa.compute_hash(message, "SHA-512")

    signed_note = rsa.sign(bank_note, private, 'SHA-512')
    with open('signed_banknote', 'wb') as s:
        s.write(signed_note)

    print(signed_note)

def verify_signature():
    public = rsa.PublicKey.load_pkcs1(file_open('public_key'))

    bank_note = file_open('toEncrypt.txt')
    signed_note = file_open('signed_banknote')

    # verify the signature to show is successful or failed
    try:
        rsa.verify(bank_note, signed_note, public)
        print("Signature successfully verified")

    except:
        print("Warning!!!! Signature could not be verified")

gen_keys()