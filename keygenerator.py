import random
import math

# generates RSA keys
# stores these keys in the keys.h file

DEFAULT_PASSWORD = "password"

f = open("keys.h", "w")
f.write("#define DEFAULT_PASSWORD \""+DEFAULT_PASSWORD+"\"\n")

BYTE_GROUP = 4
BASE = 1<<(BYTE_GROUP*8)

def writeDefinitions(name, number):
    parts = []
    hideParts = []
    while number > 0:
        hide = random.randint(1, BASE-1)
        hideParts.append(str(hide))
        parts.append(str((number % BASE)^hide))
        number /= BASE
    f.write("#define "+name+"_SIZE ("+str(len(parts))+")\n")
    f.write("#define "+name+"_DATA {"+", ".join(parts)+"}\n")
    f.write("#define "+name+"_HIDE {"+", ".join(hideParts)+"}\n")

# reference: https://www.daniweb.com/programming/software-development/code/216880/check-if-a-number-is-a-prime-number-python
def isPrime(n,PROB):
    '''returns if the number is prime. Failure rate: 1/4**PROB '''
    if n==2: return True
    if n==1 or n&1==0:return False
    # factor n-1 into 2^s * d for odd d
    s=0
    d=n-1
    while 1&d==0: # while d is even
        s+=1
        d>>=1
    for i in range(PROB):
        a=random.randint(2,n-1)
        composit=True
        # some variant of Euler's theorem?
        if pow(a,d,n)==1:
            composit=False
        if composit:
            for r in xrange(0,s):
                if pow(a,d*2**r,n)==n-1:
                    composit=False
                    break
        if composit: return False
    return True

assurance = 100

pBits = 1000
p = random.getrandbits(pBits)
while not isPrime(p, assurance):
    p = random.getrandbits(pBits)

qBits = 1100
q = random.getrandbits(qBits)
while not isPrime(q, assurance):
    q = random.getrandbits(qBits)

n = p * q

totientN = n - p - q + 1

writeDefinitions("N", n)

# e and phi(n) must be coprime
# specifically, e can be prime
# e should also be reasonably small
maxE = min(2**16, totientN-1)
e = random.randint(5, maxE)
while not isPrime(e, assurance):
    e = random.randint(5, maxE)

writeDefinitions("E", e)

# from wikipedia extended euclidean algorithm
def bezoutCoefficient(a, b):
    s = 0
    old_s = 1
    r = b
    old_r = a
    while r != 0:
        quotient = old_r / r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_s

d = bezoutCoefficient(e, totientN)
while d < 0:
    d += totientN

writeDefinitions("D", d)

f.close()
