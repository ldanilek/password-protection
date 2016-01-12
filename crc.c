#include "crc.h"
#include "bitcode.h"
#include "encrypt.h"

// uses CRC-32 described: https://en.wikipedia.org/wiki/Cyclic_redundancy_check
#define CRC_POLYNOMIAL (0x04C11DB7)

unsigned int computeCRC(FILE* inFile, int outFile)
{
    int c;
    while ((c = fgetc(inFile)) != EOF)
    {
        fdputc(c, outFile);
    }
    return 0;
}

bool checkCRC(int inFile, FILE* outFile, unsigned int checksum)
{
    int c;
    while ((c = fdgetc(inFile)) != EOF)
    {
        fputc(c, outFile);
    }
    return true;
}