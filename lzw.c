
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include "lzw.h"
#include "encrypt.h"
#include <sys/stat.h>

#define INITIAL_NUM_BITS 9
#define MAX_BITS 20
#define COMPRESSED_PREFIX_SIZE CHAR_BIT
#define COMPRESSED_PREFIX 100

#define TEST_LZW

#define EMPTY (0)

struct stack {
    char* elements;
    int capacity;
    int count;
};
typedef struct stack* CharStack;

CharStack makeStack(void)
{
    CharStack stack = calloc(sizeof(*stack), 1);
    stack->capacity = 3;
    stack->elements = calloc(sizeof(char), stack->capacity);
    return stack;
}

void freeStack(CharStack stack)
{
    free(stack->elements);
    free(stack);
}

void pushStack(CharStack stack, char elt)
{
    if (++stack->count > stack->capacity)
    {
        stack->capacity *= 2;
        stack->elements = realloc(stack->elements, stack->capacity);
    }
    stack->elements[stack->count-1] = elt;
}

char popStack(CharStack stack)
{
    return stack->elements[--stack->count];
}

#ifdef TEST_LZW
CharStack stringForCode(Array table, int code)
{
    if (!code) return makeStack();
    CharStack stack = stringForCode(table, ARRAYPREF(code));
    pushStack(stack, ARRAYCHAR(code));
    return stack;
}
#endif

// there must be at least one code with frequency <= PRUNE_USED
#define PRUNE_USED (1)

// easier to prune as array because want to look up the prefixes
// easier to output as table because don't want duplicate (PREF, CHAR)
// codes can be assigned sequentially, after the single characters
HashTable pruneTable(Array array)
{
    HashTable table = makeTable();
    int mapping[array->count+1]; // mapping[i]=j where old code i is new code j
    mapping[EMPTY] = EMPTY; // EMPTY is still the same
    int nextCode = 1;
    for (int i = 0; i < array->count; i++)
    {
        ArrayElement elt = array->elements[i];
        int eltCode = i + 1;
        Element hashElement;
        hashElement.frequency = 0;
        if (elt.PREF == EMPTY || elt.frequency > PRUNE_USED)
        {
            hashElement.PREF = mapping[elt.PREF];
            hashElement.CHAR = elt.CHAR;
            mapping[eltCode] = hashElement.CODE = nextCode++;
            // if elt.PREF == 0, its frequency has no effect so it can be neg
            hashElement.frequency = elt.frequency - PRUNE_USED;
            insertIntoTable(table, hashElement);
        }
    }
    PROGRESS("LZW table pruned, %d of %d codes remain",
        table->count, array->count);
    return table;
}

// takes single characters and puts them in HashTable 
HashTable singleCharacters(void)
{
    int code = 1;
    HashTable table = makeTable();
    for (int i = 0; i < 256; i++)
    {
        Element elt;
        elt.CHAR = i;
        elt.PREF = EMPTY;
        elt.CODE = code++;
        elt.frequency = 0;
        insertIntoTable(table, elt);
    }
    
    return table;
}

int minBitsToRepresent(int code)
{
    int numBits = INITIAL_NUM_BITS;
    while (code > 1<<numBits)
    {
        numBits++;
    }
    return numBits;
}

#ifdef TEST_LZW
void logArray(FILE* logFile, Array array)
{
    for (int i = 0; i < array->count; i++)
    {
        ArrayElement element = array->elements[i];
        if (element.frequency)
        {
            CharStack string = stringForCode(array, i+1);
            pushStack(string, '\0');
            fprintf(logFile, "%d: %s has frequency %ld\n", 
                i + 1, string->elements, element.frequency);
            freeStack(string);
        }
    }
}

void logTable(FILE* logFile, HashTable table)
{
    Array array = convertToArray(table);
    logArray(logFile, array);
    freeArray(array);
}
#endif

bool encode(int inFile, int outFile)
{
    PROGRESS("%s", "Begin encode");

#ifdef TEST_LZW
    FILE* logFile = fopen("encodeLog.lzw", "w");
#endif

    BitCache cache = {0, 0};

    putBits(COMPRESSED_PREFIX_SIZE, COMPRESSED_PREFIX, outFile, &cache);

    HashTable table = singleCharacters();

    int nextCode = table->count + 1;
    int numBits = minBitsToRepresent(table->count);

    int C = EMPTY;
    int K;
    Node whereIsC = NULL;
    unsigned long long bytesRead = 0;
    unsigned long long bitsWritten = COMPRESSED_PREFIX_SIZE;
    while ((K = fdgetc(inFile)) != EOF)
    {
        bytesRead++;
        Node lookup = searchTable(table, C, K);
        if (!lookup)
        {
            if (!whereIsC) DIE("%s", "corrupted file");

            putBits(numBits, C, outFile, &cache);
#ifdef TEST_LZW
            fprintf(logFile, "Code %d with %d bits\n", C, numBits);
#endif
            bitsWritten += numBits;
            //checkTable(table);
            bool didPrune = false;
            // increase the number of bits
            // if the next code can't be represented
            if (nextCode+1 > (1<<numBits))
            {
                // C is the last code sent and dealt with
                // the value of C doesn't matter at all anymore
                // will be reading with the old number of bits
                // until receive code 0
                // send a 0 to signify the numBits is increasing.
                //putBits(numBits, 0);
                numBits++;
                if (numBits > MAX_BITS)
                {
                    //checkTable(table);
                    Array array = convertToArray(table);
                    //checkArray(arrayVersion);
                    freeTable(table);
                    table = pruneTable(array);
                    //checkTable(table);
                    nextCode = table->count+1;
                    numBits = minBitsToRepresent(table->count);
                    freeArray(array);
                    didPrune = true;
                }
                //fprintf(stderr, "numBits increased to %d\n", numBits);
            }
            if (!didPrune)
            {
                Element elt;
                elt.PREF = C;
                elt.CHAR = K;
                elt.CODE = nextCode++;
                elt.frequency = 0;
                insertIntoTable(table, elt);
#ifdef TEST_LZW
                logTable(logFile, table);
#endif
            }
            
            lookup = searchTable(table, EMPTY, K);
            if (!lookup) DIE("lone character %c DNE", K);
        }
        C = lookup->elt.CODE;
        whereIsC = lookup;
        whereIsC->elt.frequency++;
    }
    if (C != EMPTY)
    {
        putBits(numBits, C, outFile, &cache);
#ifdef TEST_LZW
        fprintf(logFile, "Code %d with %d bits\n", C, numBits);
#endif
        bitsWritten += numBits;
    }
    // bitsWritten includes the cache.nExtra bits not actually written yet
    // but does not pad to the byte
    unsigned long long bytesWritten = bitsWritten / CHAR_BIT
    + !!(bitsWritten % CHAR_BIT);
    flushBits(outFile, &cache);

    freeTable(table);

    double bytesWrittenDouble = bytesWritten;
    double bytesReadDouble = bytesRead;
    char* writeUnits = byteCount(&bytesWrittenDouble);
    char* readUnits = byteCount(&bytesReadDouble);

    // if the encoded version is bigger, go with the other
    if (bytesWritten > bytesRead)
    {
        PROGRESS("%g%s < %g%s: use uncompressed file", bytesReadDouble,
            readUnits, bytesWrittenDouble, writeUnits);
        return false;
    }
    PROGRESS("Encoded %g%s into %g%s", bytesReadDouble,
            readUnits, bytesWrittenDouble, writeUnits);
#ifdef TEST_LZW
    fclose(logFile);
#endif
    return true;
}

void decode(int inFile, int outFile, int bytesToWrite)
{
#ifdef TEST_LZW
    FILE* logFile = fopen("decodeLog.lzw", "w");
#endif
    BitCache cache = {0, 0};
    int compressed = getBits(COMPRESSED_PREFIX_SIZE, inFile, &cache);

    if (!compressed)
    {
        PROGRESS("%s", "Archive is not encoded");
        int c;
        int bytesWritten = 0;

        if (bytesToWrite == 0) return; // make sure to test with empty files

        while ((c = fdgetc(inFile)) != EOF)
        {
            fdputc(c, outFile);
            bytesWritten++;
            if (bytesToWrite > 0 && bytesWritten >= bytesToWrite) return;
        }
        return;
    }
    if (compressed != COMPRESSED_PREFIX)
    {
        DIE("LZW prefix %d must be 0 or %d", compressed, COMPRESSED_PREFIX);
    }

    // an empty file is always made bigger, so should never get to this point
    if (bytesToWrite == 0) return;

    unsigned long long bitsRead = COMPRESSED_PREFIX_SIZE;
    unsigned long long bytesWritten = 0;

    Array table;
    HashTable hashTable = singleCharacters();
    table = convertToArray(hashTable);
    freeTable(hashTable);

    CharStack stack = makeStack();

    int oldC = EMPTY;
    int newC, C;
    char finalK = 0;
    int numBits = minBitsToRepresent(table->count);
    //bool justPruned = false;
    //int readNumBits;
    //long readFrequency;
    //fscanf(stdin, "%d:%d:%ld\n", &readNumBits, &newC, &readFrequency)
    int codeIndex = 0;
    int readC = EMPTY;
    while ((readC = getBits(numBits, inFile, &cache)) != EOF)
    {
#ifdef TEST_LZW
        fprintf(logFile, "Code %d with %d bits\n", readC, numBits);
#endif
        bitsRead += numBits;

        C = newC = readC;
        if (readC == EMPTY)
        {
            C = newC = 1<<numBits;
        }
        if (C <= EMPTY) DIE("Invalid code %d", C);
        //if (!C) fprintf(stderr, "uh oh");
        codeIndex++;
        if (C > table->count+1) {
            DIE("Code %d too big for %d, %d", C, table->count, codeIndex);
        }
        bool kwkwk = C > table->count;
        if (kwkwk)
        {
            pushStack(stack, finalK);
            C = oldC;
        }
        //checkArray(table);
        while (ARRAYPREF(C))
        {
            ArrayElement* elt = searchArray(table, C);
            elt->frequency++; // increase frequency of prefix
            pushStack(stack, ARRAYCHAR(C));
            C = ARRAYPREF(C);
        }
        // increase frequency of single character at C
        searchArray(table, C)->frequency++;

        finalK = ARRAYCHAR(C);
        fdputc(finalK, outFile);
        if (++bytesWritten >= bytesToWrite) break;
        while (stack->count)
        {
            fdputc(popStack(stack), outFile);
            if (++bytesWritten >= bytesToWrite) break;
        }
        if (bytesWritten >= bytesToWrite) break;
        if (oldC)
        {
            ArrayElement elt;
            elt.PREF = oldC;
            elt.CHAR = finalK;
            elt.frequency = !!kwkwk;
            insertIntoArray(table, elt);
        }
#ifdef TEST_LZW
        logArray(logFile, table);
#endif
        //justPruned = false;
        oldC = newC;

        // sent when numBits increases
        // detect when numBits needs to increase.
        if (table->count >= (1<<numBits) - 1)
        {
            // oldC is the last code sent and dealt with.
            numBits++;
            if (numBits > MAX_BITS)
            {
                //printf("\nprune\n");
                // prune here
                HashTable pruned = pruneTable(table);
                //justPruned = true;
                //printf("\nprune\n");
                //checkTable(pruned);
                oldC = EMPTY;
                freeArray(table);
                table = convertToArray(pruned);
                freeTable(pruned);
                numBits = minBitsToRepresent(table->count);
            }
            //continue;
        }
        
    }

    // cleanup code starts here
    freeArray(table);
    freeStack(stack);

    // bitsRead doesn't include the cache.nExtra bits which were just read
    //bitsRead += cache.nExtra;
    unsigned long long bytesRead = (bitsRead+cache.nExtra) / CHAR_BIT;
    double bytesReadDouble = bytesRead;
    char* readUnits = byteCount(&bytesReadDouble);
    double bytesWrittenDouble = bytesWritten;
    char* writeUnits = byteCount(&bytesWrittenDouble);
    PROGRESS("Decode %g%s into %g%s", bytesReadDouble, readUnits,
        bytesWrittenDouble, writeUnits);
#ifdef TEST_LZW
    fclose(logFile);
#endif
}

