
#ifndef LZW
#define LZW

#include "stringtable.h"
#include "stringarray.h"
#include "bitcode.h"
#include <stdio.h>

#define UNCOMPRESSABLE (5)

// output will begin with a one bit
// does not increase size of file
// returns whether this is possible.
// inFile is file descriptor open for reading.
// outFile is file descriptor open for writing.
bool encode(int inFile, int outFile);

// exact inverse of encode
// inFile is file descriptor for reading, outFile is for writing
void decode(int inFile, int outFile, int bytesToWrite);

#endif