#include "rsa.h"
#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <limits.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include "bitcode.h"
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

//#define ACTUALLY_RSA

//#define PMPZ(num) mpz_out_str(stdout,10,(num))
//#define PROG_MPZ(name,num) if(verbose)printf(name ": "),PMPZ(num),printf("\n")

// beginning is stored at the left end of the message

// salt is stored at the beginning of hash
#define SALT_LEN (10)
#define DIGEST_LENGTH (SHA512_DIGEST_LENGTH) // change depending on algorithm
#define HASH_LEN (SALT_LEN+DIGEST_LENGTH)

// compares n bytes, ignoring null terminators
// uses constant-time comparison
// (not that it matters since the hash value is easily attainable anyway)
bool arraysAreEqual(unsigned char* one, unsigned char* two, int n)
{
    unsigned char diff;
    for (int i = 0; i < n; i++)
    {
        diff |= one[i] ^ two[i];
    }
    return diff == 0;
}

// large enough to protect against everything but Shor's algorithm
#define MIN_KEY_BITS (1000)
#define MAX_KEY_BITS (1200)

#define SHUFFLE (10) // change this to personalize encryption

// seeds a pseudorandom number generator
// with the hash of length DIGEST_LENGTH
void seedPRNG(unsigned char* hash, gmp_randstate_t prng)
{
    gmp_randinit_mt(prng);

    // generate seed as mpz_t from unsigned char*
    mpz_t seed;
    mpz_init_set_ui(seed, 0);
    for (int i = 0; i < DIGEST_LENGTH; i++)
    {
        // make room for the new bits
        mpz_mul_ui(seed, seed, 1<<CHAR_BIT);
        // add the new bits
        mpz_add_ui(seed, seed, hash[i]);
    }
    gmp_randseed(prng, seed);
    mpz_t toshuffle;
    mpz_init(toshuffle);
    // shuffle it up a bit.
    for (int i = 0; i < SHUFFLE; i++) mpz_urandomm(toshuffle, prng, seed);
    mpz_clear(toshuffle);
    mpz_clear(seed);
}

#ifdef ACTUALLY_RSA

// generates RSA public keys N and E
// given hash of DIGEST_LENGTH characters as seed for PRNG
// input mpz_t's don't need to be initialized. should be cleared after use
void generatePublicKey(unsigned char* hash, mpz_t n, mpz_t e, mpz_t totientN)
{
    // create random number generator and seed it
    gmp_randstate_t twister;
    seedPRNG(hash, twister);

    mpz_t range;
    // range is 1<<MAX_KEY_BITS - 1<<MIN_KEY_BITS
    mpz_init_set_ui(range, 2);
    mpz_pow_ui(range, range, MAX_KEY_BITS);
    mpz_t min;
    mpz_init_set_ui(min, 2);
    mpz_pow_ui(min, min, MIN_KEY_BITS);
    mpz_sub(range, range, min);

    mpz_t p;
    mpz_init(p);
    mpz_urandomm(p, twister, range);
    mpz_add(p, min, p);
    mpz_nextprime(p, p);

    mpz_t q;
    mpz_init(q);
    mpz_urandomm(q, twister, range);
    mpz_add(q, min, p);
    mpz_nextprime(q, q);

    mpz_init(n);
    mpz_mul(n, p, q);

    // phi(n) = phi(p)*phi(q) = (p-1)(q-1) = pq-p-q+1
    mpz_init_set(totientN, n);
    mpz_sub(totientN, totientN, p);
    mpz_sub(totientN, totientN, q);
    mpz_add_ui(totientN, totientN, 1);

    mpz_clear(q);
    mpz_clear(p);

    // find maximum value for e
    if (mpz_cmp_ui(totientN, 1<<16) > 0)
    {
        mpz_init_set_ui(e, 1<<16);
    }
    else
    {
        mpz_init_set(e, totientN);
    }

    mpz_urandomm(e, twister, e);
    mpz_add_ui(e, e, 5); // should under no circumstances be less than 5
    mpz_nextprime(e, e);

    mpz_clear(range);
    mpz_clear(min);
    gmp_randclear(twister);
}

void generatePrivateKey(unsigned char* hash, mpz_t n, mpz_t d)
{
    mpz_t oldR, r, totientN;
    generatePublicKey(hash, n, oldR, totientN);
    mpz_init_set(r, totientN);
    // calculate bezout coefficient of e and totientN
    mpz_t temp;
    mpz_init(temp);
    mpz_t quotient;
    mpz_init(quotient);

    mpz_init_set_ui(d, 0);
    mpz_t oldD;
    mpz_init_set_ui(oldD, 1);

    while (mpz_sgn(r))
    {
        // quotient = old_r / r
        // old_r, r = r, old_r - quotient * r
        mpz_tdiv_qr(quotient, temp, oldR, r);
        mpz_set(oldR, r);
        mpz_set(r, temp);
        // old_s, s = s, old_s - quotient * s
        mpz_mul(temp, quotient, d);
        mpz_sub(temp, oldD, temp);
        mpz_set(oldD, d);
        mpz_set(d, temp);
    }
    mpz_set(d, oldD);
    while (mpz_sgn(d) < 0)
    {
        mpz_add(d, d, totientN);
    }

    mpz_clear(temp);
    mpz_clear(quotient);
    mpz_clear(oldD);
    mpz_clear(r);
    mpz_clear(totientN);
    mpz_clear(oldR);
}

#endif

// if password doesn't match hash, program dies
// input (uninitialized) variables for private keys
#ifdef ACTUALLY_RSA
void checkPassword(char* password, unsigned char* hash, mpz_t n, mpz_t d)
#else
void checkPassword(char* password, unsigned char* hash, gmp_randstate_t prng)
#endif
{
    bool useDefault = !password;
    if (useDefault) password = DEFAULT_PASSWORD;
    // password is null-terminated
    int passwordLength = strlen(password);
    // hash is HASH_LEN == SALT_LEN+DIGEST_LENGTH characters long

    unsigned char saltedPassword[SALT_LEN+passwordLength];
    for (int i = 0; i < SALT_LEN; i++)
    {
        saltedPassword[i] = hash[i];
    }
    for (int i = 0; i < passwordLength; i++)
    {
        saltedPassword[i + SALT_LEN] = password[i];
    }

    unsigned char passwordHash[DIGEST_LENGTH];

    SHA512(saltedPassword, SALT_LEN+passwordLength, passwordHash);

    if (!arraysAreEqual(passwordHash, hash + SALT_LEN, DIGEST_LENGTH))
    {
        DIE("%s", "Wrong Password");
    }
    else
    {
        // zero password
        if (!useDefault)
            for (int i = 0; i < passwordLength; i++) password[i] = '\0';
        PROGRESS("%s", "Password correct");
    }
#ifdef ACTUALLY_RSA
    PROGRESS("%s", "Generating private RSA keys");
    generatePrivateKey(passwordHash, n, d);
#else
    seedPRNG(passwordHash, prng);
#endif
    /*
    fprintf(stderr, "n: ");
    mpz_out_str(stderr, 10, n);
    fprintf(stderr, "\n");
    fprintf(stderr, "d: ");
    mpz_out_str(stderr, 10, d);
    fprintf(stderr, "\n");
    */
}

// pass in NULL-terminated password
// and array of length HASH_LEN to put the hash
// input (uninitialized) variables for public keys
#ifdef ACTUALLY_RSA
void hashPassword(char* password, unsigned char* hash, mpz_t n, unsigned int* e)
#else
void hashPassword(char* password, unsigned char* hash, gmp_randstate_t prng)
#endif
{
    PROGRESS("%s", "Generating password hash");
    bool useDefault = !password;
    if (useDefault) password = DEFAULT_PASSWORD;
    int passwordLength = strlen(password);
    // generate random salt
    unsigned char saltedPassword[SALT_LEN+passwordLength];
    for (int i = 0; i < SALT_LEN; i++)
    {
        unsigned char random = rand() % (UCHAR_MAX + 1);
        hash[i] = saltedPassword[i] = random;
    }
    for (int i = 0; i < passwordLength; i++)
    {
        saltedPassword[i + SALT_LEN] = password[i];
        if (!useDefault) password[i] = '\0';
    }

    // performs hash of salted password, which has SALT_LEN+passwordLength chars
    // and places the result in hash, starting after the salt.
    SHA512(saltedPassword, SALT_LEN+passwordLength, hash + SALT_LEN);

#ifdef ACTUALLY_RSA
    PROGRESS("%s", "Generating public RSA keys");
    mpz_t totientN, eBig;
    generatePublicKey(hash + SALT_LEN, n, eBig, totientN);
    *e = (unsigned int)mpz_get_ui(eBig);
    /*
    fprintf(stderr, "n: ");
    mpz_out_str(stderr, 10, n);
    fprintf(stderr, "\n");
    fprintf(stderr, "e: %u\n", *e);
    */
    mpz_clear(totientN);
    mpz_clear(eBig);
#else
    seedPRNG(hash + SALT_LEN, prng);
#endif
}

// reads from file one byte at a time until message is > goal. returns the last
// which was <= goal
void makeMessage(mpz_t message, int inFile, int maxBytes, int* totalBytes,\
    bool* reachedEOF)
{
    // for making message backwards
    mpz_t base, charInBase;
    mpz_init_set_ui(base, 1);
    mpz_init(charInBase);

    mpz_init_set_ui(message, 0);
    int bytesRead = 0;
    int c;
    while ((c = fdgetc(inFile)) != EOF)
    {
        bytesRead++;
        (*totalBytes)++;
        // make room for this character
        mpz_mul_ui(charInBase, base, c);

        mpz_mul_ui(base, base, 1<<CHAR_BIT);
        // add this character
        mpz_add(message, message, charInBase);
        if (bytesRead >= maxBytes)
        {
            mpz_clear(base);
            mpz_clear(charInBase);
            return;
        }
    }
    *reachedEOF = true;
    mpz_clear(base);
    mpz_clear(charInBase);
}

#ifdef ACTUALLY_RSA

// computes b^e mod n
void bigModularExponential(mpz_t rop, mpz_t base, mpz_t e, mpz_t n)
{
    mpz_init(rop);
    mpz_powm(rop, base, e, n); // this is where the magic happens
}

// computes b^e mod n
void modularExponential(mpz_t rop, mpz_t base, unsigned int e, mpz_t n)
{
    unsigned long int exp = e;
    mpz_init(rop);
    mpz_powm_ui(rop, base, exp, n); // this is where the magic happens
}

#else

void generateOTP(gmp_randstate_t prng, mpz_t otp, unsigned int numBits)
{
    mpz_t range;
    mpz_init_set_ui(range, 2);
    mpz_pow_ui(range, range, numBits+1);
    mpz_t min;
    mpz_init_set_ui(min, 2);
    mpz_pow_ui(min, min, numBits);
    mpz_sub(range, range, min);
    mpz_init(otp);
    mpz_urandomm(otp, prng, range);
    mpz_add(otp, min, otp);
    mpz_clear(range);
    mpz_clear(min);
    //PROGRESS("Generating One-time Pad with %u bits", numBits);
}

#endif

// if this is too big it basically becomes non-parallel execution
// and maybe the PRNG becomes really slow?
#define MAX_MESSAGE_BYTES (500)

// c = m^e mod n will convert message m into ciphertext c
void encryptRSA(char* password, int inFile, int outFile)
{
    //PROGRESS("Encrypting from %s to %s", inputName, outputName);
    STATUS("%s", "Encrypting");
    
    unsigned char hash[HASH_LEN];
#ifdef ACTUALLY_RSA
    mpz_t n;
    unsigned int e;
    hashPassword(password, hash, n, &e);
    // how many bytes can fit in a message? it must be smaller than size of n
    int maxBytes = mpz_sizeinbase(n, 2) / CHAR_BIT - 2;
#else
    gmp_randstate_t prng;
    hashPassword(password, hash, prng);
    int maxBytes = MAX_MESSAGE_BYTES;
#endif
    if (write(outFile, hash, HASH_LEN) < HASH_LEN) SYS_DIE("write");
    int totalWritten = HASH_LEN;

    /*
    mpz_t n;
    getN(n);

    unsigned int eDigits[] = E_DATA;
    unsigned int eHider[] = E_HIDE;
    unsigned int e = eDigits[0]^eHider[0];
    if (E_SIZE > 1) DIE("e is too big: %d > 1", E_SIZE);
*/
    //PROGRESS_PART("Fetch/Encrypt/Write Progress: ");
    int partialProgress = 0;
    bool reachedEOF = false;
    while (!reachedEOF)
    {
        int readLen = 0;
        //PROGRESS("%s", "Fetching message");
        mpz_t m;
        makeMessage(m, inFile, maxBytes, &readLen, &reachedEOF);

        //PROGRESS("%s", "Encrypting message");
        //printDigits("to encrypt", m);
        mpz_t c;
#ifdef ACTUALLY_RSA
        modularExponential(c, m, e, n);
#else
        unsigned int numBits = readLen * CHAR_BIT;
        mpz_init(c);
        mpz_t otp;
        generateOTP(prng, otp, numBits);
        //unsigned int otpLen = mpz_sizeinbase(otp, 2);
        //unsigned int mLen = mpz_sizeinbase(m, 2);
        mpz_xor(c, m, otp);
        mpz_clear(otp);
#endif
/*
        fprintf(stdout, "message is ");
        mpz_out_str(stdout, 10, m);
        fprintf(stdout, "\nciphertext is ");
        mpz_out_str(stdout, 10, c);
        fprintf(stdout, "\n");
        fflush(stdout);
*/
        mpz_clear(m);
        int writeLen = mpz_sizeinbase(c, 2) / CHAR_BIT + 1;
        //PROGRESS("%s", "Writing encrypted message");
        //int writeLen = c.n;
        if (write(outFile, &writeLen, sizeof(writeLen))<sizeof(writeLen))
            SYS_DIE("write");
        totalWritten += sizeof(writeLen);
        if (write(outFile, &readLen, sizeof(readLen))<sizeof(readLen))
            SYS_DIE("write");
        totalWritten += sizeof(readLen);
        unsigned char dig;
        mpz_t digitBig;
        mpz_init(digitBig);
        for (int i = 0; i < writeLen; i++)
        {
            mpz_tdiv_qr_ui(c, digitBig, c, 1<<CHAR_BIT);
            dig = mpz_get_ui(digitBig);
            if (write(outFile, &dig, sizeof(dig))<sizeof(dig)) SYS_DIE("write");
        }
        mpz_clear(digitBig);
        totalWritten += sizeof(dig)*writeLen;
        partialProgress += readLen;
        mpz_clear(c);
    }
#ifdef ACTUALLY_RSA
    mpz_clear(n);
#else
    gmp_randclear(prng);
#endif
    double bytesWrittenDouble = totalWritten;
    double bytesReadDouble = partialProgress;
    char* writeUnits = byteCount(&bytesWrittenDouble);
    char* readUnits = byteCount(&bytesReadDouble);
    STATUS("Encrypted %g%s into %g%s", bytesReadDouble, readUnits,
        bytesWrittenDouble, writeUnits);
}

// m = c^d mod n will convert ciphertext c into message m
void decryptRSA(char* password, int inFile, int outFile)
{
    STATUS("%s", "Decrypting");

    unsigned char hash[HASH_LEN];
    if (!rdhang(inFile, hash, HASH_LEN)) DIE("%s", "EOF at start");
#ifdef ACTUALLY_RSA
    mpz_t n, d;
    checkPassword(password, hash, n, d);
#else
    gmp_randstate_t prng;
    checkPassword(password, hash, prng);
#endif
    int partialProgress = HASH_LEN;
    int bytesWritten = 0;
    //int lastPercent = -1;
    int readLen;
    while (rdhang(inFile, &readLen, sizeof(readLen)))
    {
        partialProgress += sizeof(readLen);
        //PROGRESS("%s", "Fetching ciphertext");
        int writeLen;
        if (!rdhang(inFile, &writeLen, sizeof(writeLen)))
            DIE("%s","corrupt");
        partialProgress += sizeof(writeLen);
        mpz_t c, base, charInBase;
        mpz_init_set_ui(c, 0);
        mpz_init_set_ui(base, 1);
        mpz_init(charInBase);
        
        for (int i = 0; i < readLen; i++)
        {
            int character;
            if ((character = fdgetc(inFile)) == EOF)
            {
                DIE("%s", "corrupt");
            }
            mpz_mul_ui(charInBase, base, character);

            mpz_mul_ui(base, base, 1<<CHAR_BIT);
            // add this character
            mpz_add(c, c, charInBase);
        }
        
        mpz_clear(charInBase);
        mpz_clear(base);
        partialProgress += readLen;
        //PROGRESS("%s", "Decrypting cyphertext");
        mpz_t m;
#ifdef ACTUALLY_RSA
        bigModularExponential(m, c, d, n);
#else
        mpz_init(m);
        mpz_t otp;
        int numBits = writeLen * CHAR_BIT;
        generateOTP(prng, otp, numBits);
        mpz_xor(m, c, otp);
        mpz_clear(otp);
#endif
/*
        fprintf(stdout, "message is ");
        mpz_out_str(stdout, 10, m);
        fprintf(stdout, "\nciphertext is ");
        mpz_out_str(stdout, 10, c);
        fprintf(stdout, "\n");
        fflush(stdout);
*/
        mpz_clear(c);

        //printDigits("decrypted", m);
        //PROGRESS("%s", "Writing decrypted message");
        mpz_t character;
        mpz_init(character);
        for (int i = 0; i < writeLen; i++)
        {
            mpz_tdiv_qr_ui(m, character, m, 1<<CHAR_BIT);
            unsigned char byte = mpz_get_ui(character);
            fdputc(byte, outFile);
        }
        mpz_clear(character);
        mpz_clear(m);
        bytesWritten += writeLen;
    }
#ifdef ACTUALLY_RSA
    mpz_clear(n);
    mpz_clear(d);
#else
    gmp_randclear(prng);
#endif
    double bytesWrittenDouble = bytesWritten;
    double bytesReadDouble = partialProgress;
    char* writeUnits = byteCount(&bytesWrittenDouble);
    char* readUnits = byteCount(&bytesReadDouble);
    STATUS("Decrypted %g%s to yield %g%s", bytesReadDouble, readUnits, \
        bytesWrittenDouble, writeUnits);
}

