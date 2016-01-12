#include "crc.h"
#include "bitcode.h"
#include "encrypt.h"

// uses CRC described: https://en.wikipedia.org/wiki/Cyclic_redundancy_check
// CRC_N must be <= sizeof(checktype)
#define CRC_POLYNOMIAL (0x42F0E1EBA9EA3693) //(0x04C11DB7)
#define CRC_N (64) // (32)

// & with this to find leading bit of a (CRC_N - bit number)
#define LEAD_BIT_MASK (((checktype)1) << (CRC_N-1))

// & with this to find leading bit of character
#define LEAD_CHAR_BIT_MASK (((unsigned char)1) << (CHAR_BIT-1))

// initial message is 0
checktype appendBitToMessage(checktype message, bool bit)
{
    checktype firstBitSet = LEAD_BIT_MASK & message;
    message ^= firstBitSet; // clear top bit
    message <<= 1;
    message += !!bit;
    if (firstBitSet)
    {
        message ^= CRC_POLYNOMIAL;
    }
    return message;
}

void appendCharToMessage(checktype* message, unsigned char character)
{
    for (int i = 0; i < CHAR_BIT; i++)
    {
        *message = appendBitToMessage(*message, character & LEAD_CHAR_BIT_MASK);
        character <<= 1;
    }
}

void padMessage(checktype* message)
{
    for (int i = 0; i < CRC_N; i++)
    {
        *message = appendBitToMessage(*message, false);
    }
}

checktype computeCRC(FILE* inFile, int outFile)
{
    checktype message = 0;
    int c;
    while ((c = fgetc(inFile)) != EOF)
    {
        appendCharToMessage(&message, c);
        if (outFile >= 0) fdputc(c, outFile);
    }
    padMessage(&message);
    PROGRESS("Cyclic Redundancy Check has value " CHECKTYPE_FORMAT, message);
    return message;
}

bool checkCRC(int inFile, FILE* outFile, checktype checksum)
{
    checktype message = 0;
    int c;
    while ((c = fdgetc(inFile)) != EOF)
    {
        appendCharToMessage(&message, c);
        if (outFile) fputc(c, outFile);
    }
    padMessage(&message);
    if (message != checksum)
    {
        PROGRESS("Cyclic Redundancy Checksum " CHECKTYPE_FORMAT
            " != " CHECKTYPE_FORMAT, message, checksum);
    }
    else PROGRESS("Cyclic Redundancy Checksum " CHECKTYPE_FORMAT " correct",
        message);
    
    return message == checksum;
}
