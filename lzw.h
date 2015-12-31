
#ifndef LZW
#define LZW

#include "stringtable.h"
#include "stringarray.h"
#include "bitcode.h"
#include <stdio.h>

#define UNCOMPRESSABLE 5

// input must begin with a zero bit
// output will begin with a one bit
// does not increase size of file
// if this isn't possible, exit(UNCOMPRESSABLE) is called
// inFile is file descriptor open for reading.
// outFile is file descriptor open for writing.
void encode(int inFile, int outFile);

// exact inverse of encode
// inFile is file descriptor for reading, outFile is for writing
void decode(int inFile, int outFile);

#endif