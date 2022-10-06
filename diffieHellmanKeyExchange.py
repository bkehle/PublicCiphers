import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SHARED_KEY_LENGTH = 16

def generatePrivateKeys(p):
    private_key_A = random.randrange(0, p)

    private_key_B = random.randrange(0, p)
    while private_key_B == private_key_A:
        private_key_B = random.randrange(0, p)

    return private_key_A, private_key_B


def calculatePublicKeys(p, g, privateA, privateB):
    public_A = pow(g, privateA, p)
    public_B = pow(g, privateB, p)

    return public_A, public_B


def generateAliceSecretKey(B, a, p):
    s = pow(B, a, p)
    k = sha256(str(s).encode('utf-8')).hexdigest()
    return k[:SHARED_KEY_LENGTH]
    

def generateBobSecretKey(A, b, p):
    s = pow(A, b, p)
    k = sha256(str(s).encode('utf-8')).hexdigest()
    return k[:SHARED_KEY_LENGTH]

def aliceSendsBobReads(msg, Ak, Bk):
    print("Alice says, '", msg, "'", sep='')
    Ak = Ak.encode('utf-8')
    enc_cipher = AES.new(Ak, AES.MODE_CBC)
    enc_cipherText = enc_cipher.encrypt(pad(bytes(msg, 'utf-8'), AES.block_size))
    print(len(enc_cipherText))
    print("enc_cipherText =", enc_cipherText)

def bobSendsAliceReads():
    pass


if __name__ == '__main__':
    p = 37
    g = 5

    print("p =", p)
    print("g =", g)

    private_A, private_B = generatePrivateKeys(p)

    print("private A =", private_A)
    print("private B =", private_B)

    public_A, public_B = calculatePublicKeys(p, g, private_A, private_B)

    print("public A =", public_A)
    print("public B =", public_B)
    print(public_A == public_B)

    A_shared = generateAliceSecretKey(public_B, private_A, p)
    B_shared = generateBobSecretKey(public_A, private_B, p)

    print("Len A_shared =", len(A_shared), A_shared)
    print("Len B_shared =", len(B_shared), B_shared)

    msg = "Hi Bob!"

    aliceSendsBobReads(msg, A_shared, B_shared)

    print(A_shared == B_shared)
