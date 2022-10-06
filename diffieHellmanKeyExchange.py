import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from string import ascii_letters, digits

SHARED_KEY_LENGTH = 16
NUM_BYTES = 16

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
    IV = ''.join(random.choices(ascii_letters+digits, k=NUM_BYTES))
    IV = IV.encode()  # create Initialization Vector

    print("\nAlice says, '", msg, "'", sep='')
    enc_cipher = AES.new(Ak.encode('utf-8'), AES.MODE_CBC, IV)
    enc_cipherText = enc_cipher.encrypt(pad(bytes(msg, 'utf-8'), AES.block_size))

    dec_cipher = AES.new(Bk.encode('utf-8'), AES.MODE_CBC, IV)
    dec_cipherText = dec_cipher.decrypt(enc_cipherText)
    dec_cipherText = unpad(dec_cipherText, NUM_BYTES, 'pkcs7')
    print("Bob reads, '", dec_cipherText.decode(), "'\n", sep='')


def bobSendsAliceReads(msg, Bk, Ak):
    IV = ''.join(random.choices(ascii_letters+digits, k=NUM_BYTES))
    IV = IV.encode()  # create Initialization Vector

    print("\nBob says, '", msg, "'", sep='')
    enc_cipher = AES.new(Bk.encode('utf-8'), AES.MODE_CBC, IV)
    enc_cipherText = enc_cipher.encrypt(pad(bytes(msg, 'utf-8'), AES.block_size))

    dec_cipher = AES.new(Ak.encode('utf-8'), AES.MODE_CBC, IV)
    dec_cipherText = dec_cipher.decrypt(enc_cipherText)
    dec_cipherText = unpad(dec_cipherText, NUM_BYTES, 'pkcs7')
    print("Alice reads, '", dec_cipherText.decode(), "'\n", sep='')




if __name__ == '__main__':
    p = 'B10B8f96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371'
    g = 'A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5'
    p = int(p, 16)
    g = int(g, 16)

    private_A, private_B = generatePrivateKeys(p)

    # print("private A =", private_A)
    # print("private B =", private_B)

    public_A, public_B = calculatePublicKeys(p, g, private_A, private_B)

    # print("public A =", public_A)
    # print("public B =", public_B)

    A_shared = generateAliceSecretKey(public_B, private_A, p)
    B_shared = generateBobSecretKey(public_A, private_B, p)

    # print("A_shared =", len(A_shared), A_shared)
    # print("B_shared =", len(B_shared), B_shared)

    msg = input("Send a message to Bob:\n")

    aliceSendsBobReads(msg, A_shared, B_shared)

    msg = input("Send a message to Alice:\n")

    bobSendsAliceReads(msg, B_shared, A_shared)
