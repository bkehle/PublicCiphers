from Crypto.Util import number
from hashlib import sha256
from random import randrange

e = 65537
#e = 7

def keyGeneration(numBits):
   p = number.getPrime(numBits)
   q = number.getPrime(numBits)

   while p == q:
      q = number.getPrime(numBits)

   n = p * q
   euler_totient = (p - 1) * (q - 1)
   d = pow(e, -1, euler_totient)
   print("euler totient:", euler_totient)

   return (e, n), (d, n)

def encryptMessage(M, n):
   return pow(M, e, n)

def decryptMessage(C, d, n):
   return pow(C, d, n)

def aliceGetsBobCiphText(e, n):
   s = randrange(0, n)
   bobK = sha256(str(s).encode('utf-8')).hexdigest()
   print("Bob key:", bobK[:16])
   print("Bob's S:", s)
   c = pow(s, e, n)
   return c

def aliceGeneratesKey(ciph_prime, d, n):
   s = pow(ciph_prime, d, n)
   print("Alice's S:", s)
   k = sha256(str(s).encode('utf-8')).hexdigest()
   print("Alice's key:", k[:16])

def malloryTampersProcedure(PU, PR, tamper):
   c = aliceGetsBobCiphText(PU[0], PU[1])

   if tamper:
      c = 1

   aliceGeneratesKey(c, PR[0], PR[1])
   mal_s = int(pow(PU[1] + 1, (1/PU[0])))
   mal_k = sha256(str(mal_s).encode('utf-8')).hexdigest()
   print("Mallory's S:", mal_s)
   print("Mallory's key:", mal_k[:16])

if __name__ == "__main__":
   PU, PR = keyGeneration(8)

   print("Alice PU:", PU)
   print("Alice PR:", PR)

   malloryTampersProcedure(PU, PR, False)

   # s1 = m1^d mod(n)
   # s2 = m2^d mod(n)
   # m3 = m1 * m2
   # s3 = n + m3

   # n + m3







   # C = encryptMessage(88, 187)
   # print("C:", C)
   # M = decryptMessage(C, 23, 187)
   # print("M:", M)