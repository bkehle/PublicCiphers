import random
from Crypto.PublicKey import RSA


def generatePrivateKeys(p):
    private_key_A = random.randrange(0, p)

    private_key_B = random.randrange(0, p)

    while private_key_B == private_key_A:
        private_key_B = random.randrange(0, p)

    return private_key_A, private_key_B


def calculatePublicKeys(p, privateA, privateB):
    public_A = RSA.construct((p, privateA))
    public_B = RSA.construct((p, privateB))

    return public_A, public_B


def generateSecretKeys():
    pass


if __name__ == '__main__':
    p = 37
    g = 5

    private_A, private_B = generatePrivateKeys(p)

    print("private A =", private_A)
    print("private B =", private_B)

    public_A, public_B = calculatePublicKeys(p, private_A, private_B)

    #print(public_A.public_key())

    print("public A =", public_A.e)
    print("public B =", public_B.e)
    print(public_A == public_B)

    print("task 1")
