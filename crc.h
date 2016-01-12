/**
 * Computes Cyclic Redundancy Check of file before encoding and encrypting
 * Checks Cyclic Redundancy Check to confirm file has been decoded and decrypted
 * correctly.
 * Both functions read in a file and write it out
 */

#include <stdio.h>
#include <stdbool.h>

typedef unsigned long long checktype;
#define CHECKTYPE_FORMAT "%llu"

// returns CRC to check
checktype computeCRC(FILE* inFile, int outFile);

// input checksum returned by computeCRC
bool checkCRC(int inFile, FILE* outFile, checktype checksum);
