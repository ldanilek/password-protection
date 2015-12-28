
#ifndef STRING_ARRAY
#define STRING_ARRAY

#include <limits.h>
#include "stringtable.h"

// maximum size of a string table is 2^20
// therefore use int safely to store all
// codes, indices, counts, and capacities

// if change this definition, make sure to check the -i flag
typedef struct {
    int PREF;
    char CHAR;
    long frequency;
} ArrayElement;

struct Array {
    int capacity;
    int count;
    ArrayElement* elements;
};

typedef struct Array* Array;

Array makeArray(void);
Array copyArray(Array array);

void freeArray(Array array);

void insertIntoArray(Array array, ArrayElement elt);

// returns ArrayElement* so the frequency can be edited
// returns NULL if not found
// code is actually one higher than the index in the array (since EMPTY is 0)
ArrayElement* searchArray(Array array, int code);

Array convertToArray(HashTable table);
HashTable convertToTable(Array array);

// for debugging: will verify if array has a code with itself as the prefix
void checkArray(Array array);
// for debugging: will verify if table has a code with itself as the prefix
void checkTable(HashTable table);

#endif