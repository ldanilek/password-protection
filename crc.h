/**
 * Computes Cyclic Redundancy Check of file before encoding and encrypting
 * Checks Cyclic Redundancy Check to confirm file has been decoded and decrypted
 * correctly.
 * Both functions read in a file and write it out
 */

#include <stdio.h>
#include <stdbool.h>

// returns CRC to check
unsigned int computeCRC(FILE* inFile, int outFile);

// input checksum returned by computeCRC
bool checkCRC(int inFile, FILE* outFile, unsigned int checksum);