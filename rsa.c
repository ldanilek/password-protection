#include "rsa.h"
#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include "bitcode.h"
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "keys.h"

//#define PMPZ(num) mpz_out_str(stdout,10,(num))
//#define PROG_MPZ(name,num) if(verbose)printf(name ": "),PMPZ(num),printf("\n")

// this is assumed to be 4. if it changes, keygenerator.py must be updated
#define BYTE_GROUP (sizeof(unsigned int))

// most significant digits are at the end (but each digit is stored regularly)
typedef struct {
    unsigned int* digits;
    int n;
    int capacity;
} bigint;

// salt is stored at the beginning of hash
#define SALT_LEN (10)
#define HASH_LEN (SALT_LEN+SHA_DIGEST_LENGTH)

// compares n bytes, ignoring null terminators
bool arraysAreEqual(unsigned char* one, unsigned char* two, int n)
{
    return n<1 || (one[0]==two[0] && arraysAreEqual(one+1,two+1,n-1));
}

// if password doesn't match hash, program dies
void checkPassword(char* password, unsigned char* hash)
{
    bool useDefault = !password;
    if (useDefault) password = DEFAULT_PASSWORD;
    // password is null-terminated
    int passwordLength = strlen(password);
    // hash is HASH_LEN == SALT_LEN+SHA_DIGEST_LENGTH characters long

    unsigned char saltedPassword[SALT_LEN+passwordLength];
    for (int i = 0; i < SALT_LEN; i++)
    {
        saltedPassword[i] = hash[i];
    }
    for (int i = 0; i < passwordLength; i++)
    {
        saltedPassword[i + SALT_LEN] = password[i];
    }

    unsigned char passwordHash[SHA_DIGEST_LENGTH];

    SHA1(saltedPassword, SALT_LEN+passwordLength, passwordHash);

    if (!arraysAreEqual(passwordHash, hash + SALT_LEN, SHA_DIGEST_LENGTH))
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
}

// pass in NULL-terminated password
// and array of length HASH_LEN to put the hash
void hashPassword(char* password, unsigned char* hash)
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

    SHA1(saltedPassword, SALT_LEN+passwordLength, hash + SALT_LEN);
}
/*
void printDigits(char* name, bigint num)
{
    if (!verbose) return;
    printf("%s: ", name);
    for (int i = 0; i < num.n; i++)
    {
        printf("%u, ", num.digits[i]);
    }
    printf("\n");
}
*/
void normalize(bigint* num)
{
    while (num->n > 1 && num->digits[num->n - 1] == 0) num->n--;
}

// must have set the capacity of the number and digits must be on the heap
void appendDigit(bigint* n, unsigned int digit)
{
    static int usize = sizeof(unsigned int);
    if (++n->n > n->capacity)
    {
        n->capacity *= 2;
        n->digits = realloc(n->digits, usize * n->capacity);
    }
    n->digits[n->n - 1] = digit;
}

// reads from file one digit at a time until message has > goal digits
bigint makeMessage(int inFile, int goal, int* totalBytes, bool* reachedEOF)
{
    bigint message;
    message.n = 0;
    message.capacity = 10;
    message.digits = calloc(sizeof(unsigned int), message.capacity);
    unsigned char bytes[BYTE_GROUP];
    int bytesRead;
    while ((bytesRead = rdhangPartial(inFile, bytes, BYTE_GROUP)) > 0)
    {
        *totalBytes += bytesRead;
        for (int i = BYTE_GROUP-1; i >= bytesRead; i--) bytes[i] = 0;
        unsigned int accumulator = 0;
        for (int i = 0; i < BYTE_GROUP; i++)
        {
            // shift over to make room for this BYTE (8 bits)
            accumulator <<= 8;
            accumulator += bytes[i];
            //PROGRESS("read byte %d", (int)bytes[i]);
        }
        appendDigit(&message, accumulator);
        if (message.n > goal) return message;
    }
    // fingers crossed that this number is relatively prime to n
    if (bytesRead < 0) SYS_DIE("read");
    *reachedEOF = true;
    return message;
}

void convertBigint(mpz_t result, bigint a)
{
    mpz_init_set_ui(result, 0);
    mpz_t base;
    mpz_init_set_ui(base, UINT_MAX);
    mpz_add_ui(base, base, 1); // INT_MAX+1 is the base of these numbers
    mpz_t place;
    mpz_init_set_ui(place, 1); // first is the ones place
    for (int i = 0; i < a.n; i++)
    {
        mpz_t thisPlace;
        mpz_init_set_ui(thisPlace, a.digits[i]);
        mpz_mul(thisPlace, thisPlace, place);
        mpz_add(result, result, thisPlace);
        mpz_mul(place, place, base);
        mpz_clear(thisPlace);
    }
    mpz_clear(place);
    mpz_clear(base);
}

bigint convertMPZ(mpz_t a)
{
    mpz_t base;
    mpz_init_set_ui(base, UINT_MAX);
    mpz_add_ui(base, base, 1); // INT_MAX+1 is the base of these numbers
    bigint b;
    b.digits = malloc(sizeof(unsigned int));
    b.n = 0;
    b.capacity = 1;

    mpz_t digit;
    mpz_init(digit);
    while (mpz_sgn(a) > 0)
    {
        mpz_tdiv_qr(a, digit, a, base);
        appendDigit(&b, mpz_get_ui(digit));
    }
    mpz_clear(digit);
    mpz_clear(base);

    return b;
}

// computes b^e mod n
bigint bigModularExponential(bigint b, mpz_t e, mpz_t n)
{
    mpz_t base;
    convertBigint(base, b);
    mpz_t rop;
    mpz_init(rop);
    mpz_powm(rop, base, e, n); // this is where the magic happens

    bigint result = convertMPZ(rop);
    mpz_clear(base);
    mpz_clear(rop);
    return result;
}

// computes b^e mod n
bigint modularExponential(bigint b, unsigned int e, mpz_t n)
{
    mpz_t base;
    convertBigint(base, b);
    unsigned long int exp = e;
    mpz_t rop;
    mpz_init(rop);
    mpz_powm_ui(rop, base, exp, n); // this is where the magic happens

    bigint result = convertMPZ(rop);
    mpz_clear(base);
    mpz_clear(rop);
    return result;
}

#define MESSAGE_PROGRESS_GROUPS (30)

void getN(mpz_t mod)
{
    bigint n;
    unsigned int nDigits[] = N_DATA;
    unsigned int nHiders[] = N_HIDE;
    n.digits = nDigits;
    n.n = N_SIZE;
    for (int i = 0; i < n.n; i++) nDigits[i] ^= nHiders[i];
    // convert to mpz here; conversion may be slow
    convertBigint(mod, n);
}

void getD(mpz_t d)
{
    bigint dInt;
    unsigned int dData[] = D_DATA;
    unsigned int dHiders[] = D_HIDE;
    dInt.digits = dData;
    dInt.n = D_SIZE;
    for (int i = 0; i < dInt.n; i++) dData[i] ^= dHiders[i];
    convertBigint(d, dInt);
}

// c = m^e mod n will convert message m into ciphertext c
void encryptRSA(char* password, int inFile, int outFile)
{
    //PROGRESS("Encrypting from %s to %s", inputName, outputName);
    STATUS("%s", "Encrypting");
    
    unsigned char hash[HASH_LEN];
    hashPassword(password, hash);
    if (write(outFile, hash, HASH_LEN) < HASH_LEN) SYS_DIE("write");
    int totalWritten = HASH_LEN;

    mpz_t n;
    getN(n);

    unsigned int eDigits[] = E_DATA;
    unsigned int eHider[] = E_HIDE;
    unsigned int e = eDigits[0]^eHider[0];
    if (E_SIZE > 1) DIE("e is too big: %d > 1", E_SIZE);

    //PROGRESS_PART("Fetch/Encrypt/Write Progress: ");
    int partialProgress = 0;
    bool reachedEOF = false;
    while (!reachedEOF)
    {
        int readLen = 0;
        //PROGRESS("%s", "Fetching message");
        bigint m = makeMessage(inFile, N_SIZE-3, &readLen, &reachedEOF);
        //PROGRESS("%s", "Encrypting message");
        //printDigits("to encrypt", m);
        bigint c = modularExponential(m, e, n);
        free(m.digits);
        //PROGRESS("%s", "Writing encrypted message");
        int writeLen = c.n;
        if (write(outFile, &writeLen, sizeof(writeLen))<sizeof(writeLen))
            SYS_DIE("write");
        totalWritten += sizeof(writeLen);
        if (write(outFile, &readLen, sizeof(readLen))<sizeof(readLen))
            SYS_DIE("write");
        totalWritten += sizeof(readLen);
        unsigned int dig;
        for (int i = 0; i < writeLen; i++)
        {
            dig = c.digits[i];
            if (write(outFile, &dig, sizeof(dig))<sizeof(dig)) SYS_DIE("write");
        }
        totalWritten += sizeof(dig)*writeLen;
        partialProgress += readLen;
        free(c.digits);
    }
    mpz_clear(n);
    STATUS("Encrypted %d bytes into %d bytes", partialProgress, totalWritten);
}

// m = c^d mod n will convert ciphertext c into message m
void decryptRSA(char* password, int inFile, int outFile)
{
    STATUS("%s", "Decrypting");

    unsigned char hash[HASH_LEN];
    if (!rdhang(inFile, hash, HASH_LEN)) DIE("%s", "EOF at start");
    checkPassword(password, hash);

    mpz_t n, d;
    getN(n);
    getD(d);

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
        bigint c;
        c.n = readLen;
        int usize = sizeof(unsigned int);
        c.digits = calloc(readLen, usize);
        for (int i = 0; i < readLen; i++)
        {
            if (!rdhang(inFile, c.digits+i, usize)) DIE("%s","corrupt");
        }
        partialProgress += usize * readLen;
        //PROGRESS("%s", "Decrypting cyphertext");
        bigint m = bigModularExponential(c, d, n);
        free(c.digits);
        //printDigits("decrypted", m);
        //PROGRESS("%s", "Writing decrypted message");
        for (int i = 0; i < writeLen; i++)
        {
            if (i < m.n * BYTE_GROUP)
            {
                unsigned int digit = m.digits[i / BYTE_GROUP];
                unsigned char* bytes = (unsigned char*)(&digit);
                int byteIndex = i % BYTE_GROUP;
                // but number isn't stored like this.
                // 0->3, 1->2, 2->1, 3->0
                unsigned char byte = bytes[BYTE_GROUP-1-byteIndex];
                fdputc(byte, outFile);
                //PROGRESS("write byte %d", (int)(*byte));
            }
            else fdputc(0, outFile);
        }
        bytesWritten += writeLen;
        free(m.digits);
    }
    mpz_clear(n);
    mpz_clear(d);
    STATUS("Decrypted %d bytes to yield %d bytes",partialProgress,bytesWritten);
}

