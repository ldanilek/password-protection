
#ifndef LZW
#define LZW

#include "stringtable.h"
#include "stringarray.h"
#include "bitcode.h"
#include <stdio.h>

// input must begin with a zero bit
// guarenteed to increase size by maximum one bit
// removes or renames file at inputName
// creates or overwrites file at outputName
void encode(char* inputName, char* outputName);

// exact inverse of encode
// removes or renames file at inputName
// creates or overwrites file at outputName
void decode(char* inputName, char* outputName);

#endif