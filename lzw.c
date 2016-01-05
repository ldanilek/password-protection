
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
#define COMPRESSED_PREFIX_SIZE 8
#define COMPRESSED_PREFIX 100

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

// returns the code where it was inserted or found (probably nextCode)
// adds recursively a code and all of its prefixes
int insertFrequentCode(HashTable table, Array array, int code, int* nextCode)
{
    ArrayElement elt = *searchArray(array, code);
    if (elt.PREF == 0) return code;
    // if the code is in the table, all of its prefixes are too
    Node node;
    if ((node = searchTable(table, elt.PREF, elt.CHAR)))
    {
        return node->elt.CODE;
    }
    int prefixCode = insertFrequentCode(table, array, elt.PREF, nextCode);
    Element hashElement;
    hashElement.CODE = *nextCode;
    hashElement.PREF = prefixCode;
    hashElement.CHAR = elt.CHAR;
    hashElement.frequency = elt.frequency - 1;
    insertIntoTable(table, hashElement);
    return (*nextCode)++;
}

// easier to prune as array because want to look up the prefixes
// easier to output as table because don't want duplicate (PREF, CHAR)
// codes can be assigned sequentially, after the single characters
HashTable pruneTable(Array array)
{
    HashTable table = makeTable();
    int nextCode = 1;
    for (int i = 0; i < array->count; i++)
    {
        ArrayElement elt = array->elements[i];
        Element hashElement;
        hashElement.frequency = 0;
        if (elt.PREF == 0)
        {
            hashElement.PREF = 0;
            hashElement.CHAR = elt.CHAR;
            hashElement.CODE = nextCode++;
            insertIntoTable(table, hashElement);
        }
        else if (elt.frequency > 1)
        {
            insertFrequentCode(table, array, i+1, &nextCode);
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
        elt.PREF = 0;
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

bool encode(int inFile, int outFile)
{
    STATUS("%s", "Begin encode");

    putBits(COMPRESSED_PREFIX_SIZE, COMPRESSED_PREFIX, outFile);

    HashTable table = singleCharacters();

    int nextCode = table->count + 1;
    int numBits = minBitsToRepresent(table->count);

    int C = 0;
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

            putBits(numBits, C, outFile);
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
            }
            
            lookup = searchTable(table, 0, K);
            if (!lookup) DIE("lone character %c DNE", K);
        }
        C = lookup->elt.CODE;
        whereIsC = lookup;
        whereIsC->elt.frequency++;
    }
    if (C > 0)
    {
        putBits(numBits, C, outFile);
        bitsWritten += numBits;
    }
    flushBits(outFile);
    bitsWritten += 8;

    freeTable(table);

    // if the encoded version is bigger, go with the other
    if (bitsWritten/8 > bytesRead)
    {
        STATUS("%s", "Encoding increases size, so use uncompressed file");
        return false;
    }
    STATUS("Encoded %llu bytes into %llu bytes", bytesRead, bitsWritten/8);
    /*
    else
    {
        STATUS("Encoding from %s to %s: 100%%", inputName, outputName);
        fflush(stdout);
        struct stat outputStats;
        if (lstat(outputName, &outputStats)) SYS_DIE("lstat");
        off_t outSize = outputStats.st_size;
        if (remove(inputName)) SYS_ERROR("remove");
        PROGRESS("Compressed %lld bytes into %lld bytes", inSize, outSize);
    }
    */
    return true;
}

#define ARRAYPREF(C) (table->elements[(C)-1].PREF)
#define ARRAYCHAR(C) (table->elements[(C)-1].CHAR)

void decode(int inFile, int outFile, int bytesToWrite)
{
    clearGetBits(); // should be redundant, but just in case
    int compressed = getBits(COMPRESSED_PREFIX_SIZE, inFile);

    if (!compressed)
    {
        STATUS("%s", "Archive is not encoded");
        int c = 0;
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

    int oldC = 0;
    int newC, C;
    char finalK = 0;
    int numBits = minBitsToRepresent(table->count);
    //bool justPruned = false;
    //int readNumBits;
    //long readFrequency;
    //fscanf(stdin, "%d:%d:%ld\n", &readNumBits, &newC, &readFrequency)
    int codeIndex = 0;
    int readC = 0;
    while ((readC = getBits(numBits, inFile)) != EOF)
    {
        bitsRead += numBits;

        C = newC = readC;
        if (readC == 0) C = newC = 1<<numBits;
        if (C <= 0) DIE("Invalid code %d", C);
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
            elt->frequency++;
            pushStack(stack, ARRAYCHAR(C));
            C = ARRAYPREF(C);
        }
        finalK = ARRAYCHAR(C);
        fdputc(finalK, outFile);
        bytesWritten++;
        if (bytesWritten >= bytesToWrite) goto alldone;
        while (stack->count)
        {
            fdputc(popStack(stack), outFile);
            bytesWritten++;
            if (bytesWritten >= bytesToWrite) goto alldone;
        }
        if (oldC)
        {
            ArrayElement elt;
            elt.PREF = oldC;
            elt.CHAR = finalK;
            elt.frequency = kwkwk ? 1 : 0;
            insertIntoArray(table, elt);
        }
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
                //printf("size after pruning: %d\n", pruned->count);
                //checkTable(pruned);
                oldC = 0;
                freeArray(table);
                table = convertToArray(pruned);
                freeTable(pruned);
                numBits = minBitsToRepresent(table->count);
            }
            //continue;
        }
        
    }

    alldone: ;
    clearGetBits();
    freeArray(table);
    freeStack(stack);
    
    STATUS("Decode %llu bytes into %llu bytes", bitsRead/8, bytesWritten);
}

