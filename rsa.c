#include "keys.h"
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

#define PMPZ(num) mpz_out_str(stdout,10,(num))
#define PROG_MPZ(name,num) if(verbose)printf(name ": "),PMPZ(num),printf("\n")

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
        STATUS("%s", "Password correct");
    }
}

// pass in NULL-terminated password
// and array of length HASH_LEN to put the hash
void hashPassword(char* password, unsigned char* hash)
{
    PROGRESS("%s", "Generating password hash");
    int passwordLength = strlen(password);
    // generate random salt
    unsigned char saltedPassword[SALT_LEN+passwordLength];
    for (int i = 0; i < SALT_LEN; i++)
    {
        hash[i] = saltedPassword[i] = arc4random_uniform(UCHAR_MAX + 1);
    }
    for (int i = 0; i < passwordLength; i++)
    {
        saltedPassword[i + SALT_LEN] = password[i];
    }

    SHA1(saltedPassword, SALT_LEN+passwordLength, hash + SALT_LEN);
}

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
            // shift over to make room for this BYTE (8 bits)
            accumulator <<= 8;
            accumulator += bytes[i];
            //PROGRESS("read byte %d", (int)bytes[i]);
        }
        appendDigit(&message, accumulator);
        if (message.n > goal) return message;
    }
    // fingers crossed that this number is relatively prime to n
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
    mpz_init(rop);
    mpz_powm_ui(rop, base, exp, mod); // this is where the magic happens

    bigint result = convertMPZ(rop);
    mpz_clear(base);
    mpz_clear(mod);
    mpz_clear(rop);
    return result;
}

#define MESSAGE_PROGRESS_GROUPS (30)

// c = m^e mod n will convert message m into ciphertext c
void encryptRSA(char* password, char* inputName, char* outputName)
{
    STATUS("Beginning encryption from %s to %s", inputName, outputName);

    // find size of file to show nice progress
    struct stat inFileData;
    if (lstat(inputName, &inFileData)) SYS_ERROR("lstat");
    off_t inFileSize = inFileData.st_size;
    off_t progressCutoff = inFileSize / MESSAGE_PROGRESS_GROUPS;

    FILE* inFile = fopen(inputName, "r");
    if (!inFile) SYS_DIE("fopen");
    FILE* outFile = fopen(outputName, "w");
    if (!outFile) SYS_DIE("fopen");

    unsigned char hash[HASH_LEN];
    hashPassword(password, hash);
    if (fwrite(hash, 1, HASH_LEN, outFile) < HASH_LEN) SYS_DIE("fwrite");

    bigint n;
    unsigned int nDigits[] = N_DATA;
    n.digits = nDigits;
    n.n = N_SIZE;

    unsigned int eDigits[] = E_DATA;
    unsigned int e = eDigits[0];
    if (E_SIZE > 1) DIE("e is too big: %d > 1", E_SIZE);

    PROGRESS_PART("Fetch/Encrypt/Write Progress: ");
    int partialProgress = 0;
    while (!feof(inFile))
    {
        int readLen = 0;
        //PROGRESS("%s", "Fetching message");
        bigint m = makeMessage(inFile, n.n-3, &readLen);
        //PROGRESS("%s", "Encrypting message");
        //printDigits("to encrypt", m);
        bigint c = modularExponential(m, e, n);
        //PROGRESS("%s", "Writing encrypted message");
        int writeLen = c.n;
        if (fwrite(&writeLen, sizeof(writeLen), 1, outFile)<1)SYS_DIE("fwrite");
        if (fwrite(&readLen, sizeof(readLen), 1, outFile)<1)SYS_DIE("fwrite");
        for (int i = 0; i < writeLen; i++)
        {
            unsigned int dig = c.digits[i];
            if (fwrite(&dig, sizeof(dig), 1, outFile)<1)SYS_DIE("fwrite");
        }
        partialProgress += readLen;
        if (verbose && partialProgress>progressCutoff)
        {
            partialProgress %= progressCutoff;
            PROGRESS_PART("*");
        }
    }
    PROGRESS_PART("*\n");

    if (fclose(inFile)) SYS_ERROR("fclose");
    if (fclose(outFile)) SYS_ERROR("fclose");

    if (remove(inputName)) SYS_ERROR("remove");

    STATUS("%s", "RSA encryption complete");
}

// m = c^d mod n will convert ciphertext c into message m
void decryptRSA(char* password, char* inputName, char* outputName)
{
    STATUS("Beginning decryption from %s to %s", inputName, outputName);

    // find size of file to show nice progress
    struct stat inFileData;
    if (lstat(inputName, &inFileData)) SYS_ERROR("lstat");
    off_t inFileSize = inFileData.st_size;
    off_t progressCutoff = inFileSize / MESSAGE_PROGRESS_GROUPS;

    FILE* inFile = fopen(inputName, "r");
    if (!inFile) SYS_DIE("fopen");
    FILE* outFile = fopen(outputName, "w");
    if (!outFile) SYS_DIE("fopen");

    unsigned char hash[HASH_LEN];
    if (fread(hash, 1, HASH_LEN, inFile) < HASH_LEN) SYS_DIE("fread");
    checkPassword(password, hash);

    bigint d;
    unsigned int dData[] = D_DATA;
    d.digits = dData;
    d.n = D_SIZE;

    bigint n;
    unsigned int nDigits[] = N_DATA;
    n.digits = nDigits;
    n.n = N_SIZE;

    PROGRESS_PART("Fetch/Decrypt/Write Progress: ");
    int partialProgress = 0;
    int readLen;
    while (fread(&readLen, sizeof(readLen), 1, inFile))
    {
        partialProgress += sizeof(readLen);
        //PROGRESS("%s", "Fetching ciphertext");
        int writeLen;
        if (fread(&writeLen, sizeof(writeLen), 1, inFile)<1)DIE("%s","corrupt");
        partialProgress += sizeof(writeLen);
        bigint c;
        c.n = readLen;
        int usize = sizeof(unsigned int);
        c.digits = calloc(readLen, usize);
        for (int i = 0; i < readLen; i++)
        {
            if (fread(c.digits+i, usize, 1, inFile)<1)DIE("%s","corrupt");
        }
        partialProgress += usize * readLen;
        //PROGRESS("%s", "Decrypting cyphertext");
        bigint m = bigModularExponential(c, d, n);
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
                unsigned char* byte = bytes+(BYTE_GROUP-1-byteIndex);
                if (fwrite(byte, 1, 1, outFile)<1) SYS_DIE("fwrite");
                //PROGRESS("write byte %d", (int)(*byte));
            }
            else fputc(0, outFile);
        }
        if (verbose && partialProgress>progressCutoff)
        {
            partialProgress %= progressCutoff;
            PROGRESS_PART("*");
        }
    }
    PROGRESS_PART("*\n");

    if (fclose(inFile)) SYS_ERROR("fclose");
    if (fclose(outFile)) SYS_ERROR("fclose");

    if (removeOriginal && remove(inputName)) SYS_ERROR("remove");

    STATUS("%s", "RSA decryption complete");
}

