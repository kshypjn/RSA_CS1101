import secrets
import random
import hashlib


# Miller Rabin Primality Test

def primality_testMR(number, rounds=40):
    # Miller Rabin primality test with rounds defaulted to 40 as found on the internet Check out :
    # https://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # The above weblink explains why the optimal number is 40
    if number > 1:
        if number == 2 or number == 3 or number == 5:
            return True
        if number % 2 == 0:
            # EVEN NUMBERS ARE COMPOSITE DUH
            return False
        # for expressing n-1 = m*(2**k)
        exponent = number - 1
        r = 0
        while exponent % 2 == 0:
            exponent //= 2
            r += 1
            # perform rounds of iterations
            for i in range(rounds):
                a = secrets.randbelow(number - 4) + 2
                # pow function takes 2 mandatory arguments and one optional arg (base,exponent and modulus)
                x = pow(a, exponent, number)
                if x == 1 or x == number - 1:
                    continue
                for j in range(r - 1):
                    x = pow(x, 2, number)
                    if x == number - 1:
                        break
                else:
                    return False
            return True


# checking if the number is actually prime
def isTheNumberAmazonPrime(number):
    return primality_testMR(number)


def drawMeAPrimeNumber():
    # According to the python documentation for the secrets module 32 bits is safe and good to use .
    # ^ https://docs.python.org/3/library/secrets.html#module-secrets
    num = secrets.randbits(32)
    ourNumber = secrets.randbelow(num)
    while 1 > 0:
        if isTheNumberAmazonPrime(ourNumber):
            return ourNumber
        else:
            ourNumber = ourNumber + 1


# HCF for finding the highest common factor and it will be helpful in checking if two numbers are co-prime
def hcf(a, b):
    while b:
        a, b = b, a % b
    return a


# Generating Public Key
def E_Generator(fn):
    elephant = random.randint(2, fn)
    while 1 > 0:
        if hcf(elephant, fn) == 1:
            return elephant
        else:
            elephant += 1


# Extended Euclid Algo - to be used in the mod_inverse function
# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#:~:text=The%20extended%20Euclidean%20algorithm%20is%20the%20essential%20tool%20for%20computing,fields%20of%20non%2Dprime%20order
def ExtEuclid(a, b):
    if a % b == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = ExtEuclid(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y


def mod_inverse(a, b):
    # Apply the extended Euclidean algorithm
    gcd, x, y = ExtEuclid(a, b)

    # If a and m are not co-prime, then there is no modular inverse
    if gcd != 1:
        return None
    # Return the modular inverse
    return x % b


# ENCRYPT FUNCTION
def encrypt(publicKey, N, message):
    cryptic = []
    for element in message:
        # Storing Strings as their ASCII values - ASCII acting as a proxy
        code = ord(element)
        # Converting the element to a cryptic number
        final = pow(code, publicKey, N)
        # Appending it to the cryptic message 'c'
        cryptic.append(final)
    return cryptic


# DECRYPT  FUNCTION
def decrypt(privateKey, N, crypticMessage):
    answer = ""
    for element in crypticMessage:
        # converting a string to int
        adapt = int(element)
        # decrypting each element in the cryptic message using (adapt**privateKey)%N
        improvise = pow(adapt, privateKey, N)
        # Converts the integer to return string representation of the character in ASCII
        overcome = chr(improvise)
        answer += overcome

    return answer


# HASH/SIGNING FUNCTION FUNCTION
def hashFunction(message):
    # Using Hashlib to encode the message
    hashed = hashlib.sha256(message.encode("UTF-8")).hexdigest()
    return hashed


# VERIFICATION FUNCTION
def verify(receivedHashed, message):
    # Assigning ourHashed to the encode and secure the message
    ourHashed = hashFunction(message)
    # Checking if the receivedHased is the sane as the encoded message
    if receivedHashed == ourHashed:
        m = decrypt(d, N, c)
        return f"Verification Successful \nMessage : {m}"
    else:
        return "Verification Unsuccessful! "


# RUNNING

p = drawMeAPrimeNumber()
q = drawMeAPrimeNumber()
print(f"p:{p} \nq:{q}")
N = p * q
print(f"N:{N}")

phi_N = (p - 1) * (q - 1)
print(f"phi_N:{phi_N}")
# Public Key
e = E_Generator(phi_N)
print(f"e = PublicKey = {e}")
# Private Key
d = mod_inverse(e, phi_N)
print(f"d = privateKey = {d}")
# Input Message
msg = input("ENTER YOUR MESSAGE HERE: ")
# encrypted text
c = encrypt(e, N, msg)
"""
WITHOUT HASHING:
c = encrypt(e, N, msg)
print(f"Encrypted Version:{c}")
m = decrypt(d, N, c)
print(f"decrypted Version:{m}")"""

secureMessage = hashFunction(msg)
encryptedMessage = encrypt(d, N, secureMessage)
print("Your encrypted hashed message is: ")
print(encryptedMessage)

decrypted_msg = decrypt(e, N, encryptedMessage)
print("Your decrypted message is:")
print(decrypted_msg)
print("Verification process...")
print(verify(decrypted_msg, msg))
