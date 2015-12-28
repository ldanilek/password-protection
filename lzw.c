
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
    PROGRESS("%s", "LZW table pruned");
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

void encode(char* inputName, char* outputName)
{
    STATUS("Beginning encode from %s to %s", inputName, outputName);

    FILE* input = fopen(inputName, "r");
    if (!input) SYS_DIE("fopen");
    FILE* output = fopen(outputName, "w");
    if (!output) SYS_DIE("fopen");

    putBits(1, 1, output);

    HashTable table = singleCharacters();

    int nextCode = table->count + 1;
    int numBits = minBitsToRepresent(table->count);

    int C = 0;
    int K;
    Node whereIsC = NULL;
    while ((K = fgetc(input)) != EOF)
    {
        Node lookup = searchTable(table, C, K);
        if (!lookup)
        {
            if (!whereIsC) DIE("%s", "corrupted file");
            whereIsC->elt.frequency++;
            putBits(numBits, C, output);
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
    }
    if (C > 0)
    {
        putBits(numBits, C, output);
    }
    flushBits(output);

    freeTable(table);

    if (fclose(input)) SYS_ERROR("fclose");
    if (fclose(output)) SYS_ERROR("fclose");

    // if the encoded version is bigger, go with the other
    struct stat outputStats;
    if (lstat(outputName, &outputStats)) SYS_DIE("lstat");
    struct stat inputStats;
    if (lstat(inputName, &inputStats)) SYS_DIE("lstat");
    off_t outSize = outputStats.st_size;
    off_t inSize = inputStats.st_size;
    if (outSize > inSize)
    {
        STATUS("%lld > %lld, so use uncompressed file", outSize, inSize);
        rename(inputName, outputName);
    }
    else
    {
        if (remove(inputName)) SYS_ERROR("remove");
        
        STATUS("%s", "Completed Encode");
    }
}

#define ARRAYPREF(C) (table->elements[(C)-1].PREF)
#define ARRAYCHAR(C) (table->elements[(C)-1].CHAR)

void decode(char* inputName, char* outputName)
{
    STATUS("Beginning decode from %s to %s", inputName, outputName);

    FILE* inFile = fopen(inputName, "r");
    if (!inFile) SYS_DIE("fopen");

    int compressed;
    if ((compressed = getBits(1, inFile)) == EOF) DIE("%s", "Corrupt file");
    if (!compressed)
    {
        fclose(inFile);
        if (rename(inputName, outputName)) SYS_DIE("rename");
        STATUS("%s is not encoded", inputName);
        return;
    }

    FILE* outFile = fopen(outputName, "w");
    if (!outFile) SYS_DIE("fopen");

    Array table;
    HashTable hashTable = singleCharacters();
    table = convertToArray(hashTable);
    freeTable(hashTable);

    CharStack stack = makeStack();

    int oldC = 0;
    int newC, C;
    char finalK;
    int numBits = minBitsToRepresent(table->count);
    bool frozen, pleaseFreeze;
    frozen=pleaseFreeze = false;
    //bool justPruned = false;
    //int readNumBits;
    //long readFrequency;
    //fscanf(stdin, "%d:%d:%ld\n", &readNumBits, &newC, &readFrequency)
    int codeIndex = 0;
    int readC = 0;
    while ((readC = getBits(numBits, inFile)) != EOF)
    {
        C = newC = readC;
        if (readC == 0) C = newC = 1<<numBits;
        if (C < 0) DIE("%s", "Negative code");
        if (C == 0) DIE("%s", "zero code");
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
        else
        {
            // increase frequency of this code
            ArrayElement* elt = searchArray(table, C);
            elt->frequency++;
        }
        //checkArray(table);
        while (ARRAYPREF(C))
        {
            pushStack(stack, ARRAYCHAR(C));
            C = ARRAYPREF(C);
        }
        finalK = ARRAYCHAR(C);
        fputc(finalK, outFile);
        while (stack->count)
        {
            fputc(popStack(stack), outFile);
        }
        if (oldC && !frozen)
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

    freeArray(table);
    freeStack(stack);

    if (fclose(outFile)) SYS_ERROR("fclose");
    if (fclose(inFile)) SYS_ERROR("fclose");

    if (remove(inputName)) SYS_ERROR("remove");

    STATUS("%s", "Completed decode");
}

