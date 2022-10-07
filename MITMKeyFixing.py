import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from string import ascii_letters, digits

from diffieHellmanKeyExchange import SHARED_KEY_LENGTH
from diffieHellmanKeyExchange import NUM_BYTES

def generatePrivateKeys(p):
    private_key_A = random.randrange(0, p)

    private_key_B = random.randrange(0, p)
    while private_key_B == private_key_A:
        private_key_B = random.randrange(0, p)

    private_key_C = random.randrange(0, p)
    while private_key_C == private_key_A or private_key_C == private_key_B:
        private_key_C = random.randrange(0, p)

    return private_key_A, private_key_B, private_key_C

def calculatePublicKeys(p, g, privateA, privateB):
   public_A = pow(g, privateA, p)
   public_B = pow(g, privateB, p)
   public_M = pow(g, private_M, p)

   return public_A, public_B, public_M

def generateAliceSecretKey(B, a, p):
    s = pow(B, a, p)
    k = sha256(str(s).encode('utf-8')).hexdigest()
    return k[:SHARED_KEY_LENGTH]
    

def generateBobSecretKey(A, b, p):
    s = pow(A, b, p)
    k = sha256(str(s).encode('utf-8')).hexdigest()
    return k[:SHARED_KEY_LENGTH]


def aliceSendsMalloryInterceptsBobReads(msg, AMk, BMk):
    IV = ''.join(random.choices(ascii_letters+digits, k=NUM_BYTES))
    IV = IV.encode()  # create Initialization Vector

    print("\nAlice says, '", msg, "'\n", sep='')
    enc_cipher = AES.new(AMk.encode('utf-8'), AES.MODE_CBC, IV)
    enc_cipherText = enc_cipher.encrypt(pad(bytes(msg, 'utf-8'), AES.block_size))

    dec_cipher = AES.new(AMk.encode('utf-8'), AES.MODE_CBC, IV)
    dec_cipherText = dec_cipher.decrypt(enc_cipherText)
    dec_cipherText = unpad(dec_cipherText, NUM_BYTES, 'pkcs7')
    
    MIV = ''.join(random.choices(ascii_letters+digits, k=NUM_BYTES))
    MIV = MIV.encode()

    print("Mallory has intercepted the message!")
    tampered_msg = input("What should Mallory change the message to?\n")
    print("\nMallory changes the message to => ", "'", tampered_msg, "' ", "and sends it to Bob", sep='')

    m_cipher = AES.new(BMk.encode('utf-8'), AES.MODE_CBC, MIV)
    m_CipherText = m_cipher.encrypt(pad(bytes(tampered_msg, 'utf-8'), AES.block_size))

    m_dec_cipher = AES.new(BMk.encode('utf-8'), AES.MODE_CBC, MIV)
    m_dec_cipherText = m_dec_cipher.decrypt(m_CipherText)
    m_dec_cipherText = unpad(m_dec_cipherText, NUM_BYTES, 'pkcs7')
    print("Bob reads, '", m_dec_cipherText.decode(), "'\n", sep='')


def bobSendsMalloryInterceptsAliceReads(msg, BMk, AMk):
    IV = ''.join(random.choices(ascii_letters+digits, k=NUM_BYTES))
    IV = IV.encode()  # create Initialization Vector

    print("\nBob says, '", msg, "'\n", sep='')
    enc_cipher = AES.new(BMk.encode('utf-8'), AES.MODE_CBC, IV)
    enc_cipherText = enc_cipher.encrypt(pad(bytes(msg, 'utf-8'), AES.block_size))

    dec_cipher = AES.new(BMk.encode('utf-8'), AES.MODE_CBC, IV)
    dec_cipherText = dec_cipher.decrypt(enc_cipherText)
    dec_cipherText = unpad(dec_cipherText, NUM_BYTES, 'pkcs7')
    

    print("Mallory has intercepted the message!")
    tampered_msg = input("What should Mallory change the message to?\n")
    print("\nMallory changes the message to => ", "'", tampered_msg, "' ", "and sends it to Alice", sep='')


    MIV = ''.join(random.choices(ascii_letters+digits, k=NUM_BYTES))
    MIV = MIV.encode()

    m_cipher = AES.new(AMk.encode('utf-8'), AES.MODE_CBC, MIV)
    m_CipherText = m_cipher.encrypt(pad(bytes(tampered_msg, 'utf-8'), AES.block_size))

    m_dec_cipher = AES.new(AMk.encode('utf-8'), AES.MODE_CBC, MIV)
    m_dec_cipherText = m_dec_cipher.decrypt(m_CipherText)
    m_dec_cipherText = unpad(m_dec_cipherText, NUM_BYTES, 'pkcs7')
    print("Alice reads, '", m_dec_cipherText.decode(), "'\n", sep='')


if __name__ == '__main__':
   p = 'B10B8f96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371'
   g = 'A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5'
   p = int(p, 16)
   g = int(g, 16)

   private_A, private_B, private_M = generatePrivateKeys(p)

   #print("privA =", private_A)
   #print("privB =", private_B)

   public_A, public_B, public_M = calculatePublicKeys(p, g, private_A, private_B)

   #print("Alice's public key = ", str(public_A)[:SHARED_KEY_LENGTH], "...", sep='')
   #print("Bob's public key = ", str(public_B)[:SHARED_KEY_LENGTH], "...\n", sep='')

   # Mallory impersonates as Bob
   not_public_B = public_M
   print("Mallory changes Bob's public key to his => ", str(public_M)[:SHARED_KEY_LENGTH], "...", sep='')
   A_shared = generateAliceSecretKey(not_public_B, private_A, p)
   print("Alice's shared secret key with 'Bob' is generated...\n")
   #M_shared_with_Alice = mallorySecretKey(public_A, private_M, p)
   #print(A_shared == M_shared_with_Alice)

   # Mallory impersonates as Alice
   not_public_A = public_M
   print("Mallory changes Alice's public key to his => ", str(public_M)[:SHARED_KEY_LENGTH], "...", sep='')
   B_shared = generateBobSecretKey(not_public_A, private_B, p)
   print("Bob's shared secret key with 'Alice' is generated...\n")
   #M_shared_with_Bob = mallorySecretKey(public_B, private_M, p)
   #print(B_shared == M_shared_with_Bob)

   #print("Alice and Bob's secret keys are generated")
   print("Are Alice and Bob's shared keys equal? => ", A_shared == B_shared, "... they are talking to Mallory!\n", sep='')

   msg = input("Alice sends a message to Bob:\n")

   aliceSendsMalloryInterceptsBobReads(msg, A_shared, B_shared)

   msg = input("Bob sends a message to Alice:\n")

   bobSendsMalloryInterceptsAliceReads(msg, B_shared, A_shared)





