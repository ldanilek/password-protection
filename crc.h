/**
 * Computes Cyclic Redundancy Check of file before encoding and encrypting
 * Checks Cyclic Redundancy Check to confirm file has been decoded and decrypted
 * correctly.
 * Both functions read in a file and write it out
 */

#include <stdio.h>
#include "bitcode.h"

typedef unsigned long long checktype;
#define CHECKTYPE_FORMAT "%llu"

// returns CRC to check
// if outFile is <0, doesn't use it
checktype computeCRC(FILE* inFile, int outFile);

// input checksum returned by computeCRC
// if outFile is NULL, doesn't use it
bool checkCRC(int inFile, FILE* outFile, checktype checksum);
