#include "keys.h"
#include "rsa.h"
#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <limits.h>

#define BYTE_GROUP (4)

typedef unsigned long long bbig;

// to read a message in, this must be a multiple of 8 (bits)
#define BASE (((bbig)1)<<((bbig)BYTE_GROUP*8))

// most significant digits are at the end (but each digit is stored regularly)
typedef struct {
    unsigned int* digits;
    int n;
    int capacity;
} bigint;

void normalize(bigint* num)
{
    while (num->n > 1 && num->digits[num->n - 1] == 0) num->n--;
}

bool greaterThan(bigint one, bigint two)
{
    // remove trailing zeroes
    normalize(&one);
    normalize(&two);
    if (one.n > two.n) return true;
    if (one.n < two.n) return false;
    for (int i = one.n - 1; i >= 0; i--)
    {
        if (one.digits[i] > two.digits[i]) return true;
        if (one.digits[i] < two.digits[i]) return false;
    }
    return false;
}

void appendDigit(bigint* n, unsigned int digit)
{
    int usize = sizeof(unsigned int);
    if (++n->n > n->capacity)
    {
        n->capacity *= 2;
        n->digits = realloc(n->digits, usize*n->capacity);
    }
    n->digits[n->n-1] = accumulator;
}

// reads from file one digit at a time until message has > goal digits
bigint makeMessage(FILE* inFile, int goal, int* totalBytes)
{
    bigint message;
    message.n = 0;
    message.capacity = 10;
    message.digits = calloc(sizeof(unsigned int), message.capacity);
    unsigned char bytes[BYTE_GROUP];
    int bytesRead;
    while ((bytesRead = fread(bytes, 1, BYTE_GROUP, inFile)))
    {
        *totalBytes += bytesRead;
        for (int i = BYTE_GROUP-1; i >= bytesRead; i--) bytes[i] = 0;
        unsigned int accumulator = 0;
        for (int i = 0; i < BYTE_GROUP; i++)
        {
            accumulator <<= 1;
            accumulator += bytes[i];
        }
        appendDigit(&message, accumulator);
        if (message.n > goal) return message;
    }
    // fingers crossed that this number is relatively prime to n
    return message;
}

/*
// restriction: a > n
// a = a - b
void subtract(bigint* a, bigint b)
{
    for (int i = 0; i < b.n; i++)
    {
        if (a->digits[i] < b.digits[i])
        {
            // carry. hopefully the unsigned int arithmetic will just work
            int j = i+1;
            while (a->digits[j] == 0) a->digits[j++]--;
            a->digits[j]--;
        }
        a->digits[i] -= b.digits[i];
    }
    normalize(a);
}

// a = a mod n
void modulo(bigint* a, bigint n)
{
    while (greaterThan(*a, n))
    {
        subtract(a, n);
    }
}

// *a += b * c
// the overflow gets placed in a+1
void addProductAndCarry(unsigned int* a, unsigned int b, unsigned int c)
{
    bbig total = ((bbig)a)+((bbig)b)*((bbig)c);
    a[1] = total / BASE;
    a[0] = total;
}

// retval = a * b
bigint multiply(bigint a, bigint b)
{
    bigint product;
    // no matter how much overflow there is,
    // there can't be more than a.n+b.n digits
    product.n = a.n + b.n;
    product.digits = calloc(sizeof(unsigned int), product.n);
    for (int i = 0; i < a.n; i++)
    {
        for (int j = 0; j < b.n; j++)
        {
            addProductAndCarry(product.digits+i+j, a.digits[i], b.digits[j]);
        }
    }
    return product;
}

// performs a modular multiplication, a = a * b mod n
void multiplyBy(bigint* a, bigint b, bigint n)
{
    bigint product = multiply(*a, b);
    free(a->digits);
    *a = product;
    modulo(a, n);
}*/

/*

// computes b^e mod n
// input restraints: m > 1 and b < n
// algorithm from https://en.wikipedia.org/wiki/Modular_exponentiation
bigint modularExponential(bigint b, unsigned int e, bigint n)
{
    bigint result;
    result.capacity = 1;
    result.n = 1;
    result.digits = malloc(sizeof(unsigned int));
    result.digits[0] = 1;
    while (e)
    {
        if (e & 1)
        {
            multiplyBy(&result, b, n);
        }
        e >>= 1;
        // copy base so can square it
        bigint bCopy;
        bCopy.n = b.n;
        bCopy.digits = malloc(b.n * sizeof(unsigned int));
        for (int i = 0; i < b.n; i++) bCopy.digits[i] = b.digits[i];
        multiplyBy(&b, bCopy, n);
        free(bCopy.digits);
    }
    return result;
}

// divides by two via a bitshift
void shiftRight(bigint* d)
{

}

bigint bigModularExponential(bigint b, bigint d, bigint n)
{
    bigint result;
    result.capacity = 1;
    result.n = 1;
    result.digits = malloc(sizeof(unsigned int));
    result.digits[0] = 1;
    normalize(&d);
    while (d.n > 1 || d.digits[0] > 0)
    {
        if (d.digits[0] & 1)
        {
            multiplyBy(&result, b, n);
        }
        shiftRight(&d);
        // copy base so can square it
        bigint bCopy;
        bCopy.n = b.n;
        bCopy.digits = malloc(b.n * sizeof(unsigned int));
        for (int i = 0; i < b.n; i++) bCopy.digits[i] = b.digits[i];
        multiplyBy(&b, bCopy, n);
        free(bCopy.digits);
    }
    return result;
}*/

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

    return b;
}

// computes b^e mod n
bigint bigModularExponential(bigint b, bigint e, bigint n)
{
    mpz_t base, exp, mod;
    convertBigint(base, b);
    convertBigint(exp, e);
    convertBigint(mod, n);
    mpz_t rop;
    mpz_init(rop);
    mpz_powm(rop, base, exp, mod); // this is where the magic happens
    bigint result = convertMPZ(rop);
    mpz_clear(base);
    mpz_clear(exp);
    mpz_clear(mod);
    mpz_clear(rop);
    return result;
}

// computes b^e mod n
bigint modularExponential(bigint b, unsigned int e, bigint n)
{
    mpz_t base, mod;
    convertBigint(base, b);
    unsigned long int exp = e;
    convertBigint(mod, n);
    mpz_t rop;
    mpz_powm_ui(rop, base, exp, mod); // this is where the magic happens
    bigint result = convertMPZ(rop);
    mpz_clear(base);
    mpz_clear(mod);
    mpz_clear(rop);
    return result;
}

// c = m^e mod n will convert message m into ciphertext c
void encryptRSA(char* password, char* inputName, char* outputName)
{
    STATUS("Beginning encryption from %s to %s", inputName, outputName);

    FILE* inFile = fopen(inputName, "r");
    if (!inFile) SYS_DIE("fopen");
    FILE* outFile = fopen(outputName, "w");
    if (!outFile) SYS_DIE("fopen");

    bigint n;
    unsigned int nDigits[] = N_DATA;
    n.digits = nDigits;
    n.n = N_SIZE;

    unsigned int eDigits[] = E_DATA;
    unsigned int e = eDigits[0];
    if (E_SIZE > 1) DIE("e is too big: %d > 1", E_SIZE);

    while (!feof(inFile))
    {
        int readLen = 0;
        PROGRESS("%s", "Fetching message");
        bigint m = makeMessage(inFile, n.n-3, &readLen);
        PROGRESS("%s", "Encrypting message");
        bigint c = modularExponential(m, e, n);
        PROGRESS("%s", "Writing encrypted message");
        int writeLen = c.n;
        if (fwrite(&writeLen, sizeof(writeLen), 1, outFile)<1)SYS_DIE("fwrite");
        if (fwrite(&readLen, sizeof(readLen), 1, outFile)<1)SYS_DIE("fwrite");
        for (int i = 0; i < c.n; i++)
        {
            unsigned int dig = c.digits[i];
            if (fwrite(&dig, sizeof(dig), 1, outFile)<1)SYS_DIE("fwrite");
        }
    }

    if (fclose(inFile)) SYS_ERROR("fclose");
    if (fclose(outFile)) SYS_ERROR("fclose");

    STATUS("%s", "RSA encryption complete");
}

// m = c^d mod n will convert ciphertext c into message m
void decryptRSA(char* password, char* inputName, char* outputName)
{
    STATUS("Beginning decryption from %s to %s", inputName, outputName);

    FILE* inFile = fopen(inputName, "r");
    if (!inFile) SYS_DIE("fopen");
    FILE* outFile = fopen(outputName, "w");
    if (!outFile) SYS_DIE("fopen");

    bigint d;
    unsigned int dData[] = D_DATA;
    d.digits = dData;
    d.n = D_SIZE;

    bigint n;
    unsigned int nDigits[] = N_DATA;
    n.digits = nDigits;
    n.n = N_SIZE;

    int readLen;
    while (fread(&readLen, sizeof(readLen), 1, inFile))
    {
        PROGRESS("%s", "Fetching ciphertext");
        int writeLen;
        if (fread(&writeLen, sizeof(writeLen), 1, inFile)<1)DIE("%s","corrupt");
        bigint c;
        c.n = readLen;
        int usize = sizeof(unsigned int);
        c.digits = calloc(readLen, usize);
        for (int i = 0; i < readLen; i++)
        {
            if (fread(c.digits+i, usize, 1, inFile)<1)DIE("%s","corrupt");
        }
        PROGRESS("%s", "Decrypting cyphertext");
        bigint m = bigModularExponential(c, d, n);
        PROGRESS("%s", "Writing decrypted message");
        for (int i = 0; i < writeLen; i++)
        {
            if (i < m.n * BYTE_GROUP)
            {
                unsigned int digit = m.digits[i / BYTE_GROUP];
                char* byte = ((char*)(&digit)) + (i % BYTE_GROUP);
                if (fwrite(byte, 1, 1, outFile)<1) SYS_DIE("fwrite");
            }
            else fputc(0, outFile);
        }
    }

    STATUS("%s", "RSA decryption complete");
}

