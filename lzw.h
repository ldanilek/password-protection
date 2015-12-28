
#ifndef LZW
#define LZW

#include "stringtable.h"
#include "stringarray.h"
#include "bitcode.h"
#include <stdio.h>

void encode(char* inputName, char* outputName);

void decode(char* inputName, char* outputName);

#endif