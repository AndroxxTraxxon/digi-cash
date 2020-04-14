from Crypto import Random
from Crypto.Random import random
import hashlib
from util.custom_exceptions import BadSignature, ChecksumConflict
def is_prime(n, k=128):
    """ Test if a number is prime        
        Args:
            n -- int -- the number to test
            k -- int -- the number of tests to do        
    return True if n is prime
    """
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False    

    return True


def generate_prime_candidate(length):
    """ Generate an odd integer randomly        
        Args:
            length -- int -- the length of the number to generate, in bits        
            
        return a integer
    """
    # generate random bits
    p = int.from_bytes(Random.get_random_bytes(length), 'big')
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1    
    return p

def generate_prime_number(length=128):
    """ Generate a prime
        Args:
            length -- int -- length of the prime to generate, in bits
         
        return a prime
    """
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p

def gcd(a, b):
    A = max(a, b)
    B = min(a, b)
    C = A % B
    while C != 0:
        A, B = B, C
        C = A % B
    
    return B

def modulo_multiplicative_inverse(A, M):
    """
    Assumes that A and M are co-prime
    Returns multiplicative modulo inverse of A under M
    """
    # Find gcd using Extended Euclid's Algorithm
    _, x, _ = extended_euclid_gcd(A, M)

    # In case x is negative, we handle it by adding extra M
    # Because we know that multiplicative inverse of A in range M lies
    # in the range [0, M-1]
    if x < 0:
        x += M
    
    return x

def extended_euclid_gcd(a, b):
    """
    Returns a list `result` of size 3 where:
    Referring to the equation ax + by = gcd(a, b)
        result[0] is gcd(a, b)
        result[1] is x
        result[2] is y 
    """
    s = 0; old_s = 1
    t = 1; old_t = 0
    r = b; old_r = a

    while r != 0:
        quotient = old_r//r # In Python, // operator performs integer or floored division
        # This is a pythonic way to swap numbers
        # See the same part in C++ implementation below to know more
        old_r, r = r, old_r - quotient*r
        old_s, s = s, old_s - quotient*s
        old_t, t = t, old_t - quotient*t
    return [old_r, old_s, old_t]
    

def generate_keychain():
    print("Generating Public/Private Keychain")
    p = generate_prime_number()
    q = p
    while q == p:
        q = generate_prime_number()
        
    n = p * q
    phi = (p-1) * (q-1)
    e = generate_prime_number()
    while gcd(e, phi) > 1:
        e = generate_prime_number()

    d = modulo_multiplicative_inverse(e, phi)
    print("Done Generating Keychain")
    return (e, d, n)

def validate_signature(checksum:int, signature:int, key:tuple, verbose=False):
    _validation = pow(signature, *key) # key format: (e, n) : (public key, public modulus)
    if verbose:
        print(_validation)
        print(checksum)
    if checksum != _validation:
        raise BadSignature()
    return True

def validate_checksum(data:bytes, checksum:bytes, verbose=False):
    if isinstance(data, str):
        data = data.encode('utf-8')
    _validation = hashlib.sha256(data).digest()
    if verbose:
        print(_validation)
        print(checksum)
    if checksum != _validation:
        raise ChecksumConflict()
    return True