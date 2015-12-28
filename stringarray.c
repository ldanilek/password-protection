#include "stringarray.h"
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "encrypt.h"

Array makeArray(void)
{
    Array array = calloc(sizeof(*array), 1);
    array->capacity = 3;
    array->elements = calloc(sizeof(ArrayElement), array->capacity);
    return array;
}

void freeArray(Array array)
{
    free(array->elements);
    free(array);
}

Array copyArray(Array array)
{
    Array copy = makeArray();
    for (int i = 0; i < array->count; i++)
    {
        insertIntoArray(copy, array->elements[i]);
    }
    return copy;
}

void insertIntoArray(Array array, ArrayElement elt)
{
    if (++array->count > array->capacity)
    {
        array->capacity *= 2;
        array->elements = realloc(array->elements,
            sizeof(ArrayElement) * array->capacity);
    }
    array->elements[array->count-1] = elt;
}

ArrayElement* searchArray(Array array, int code)
{
    assert(code > 0);
    return array->elements + (code - 1);
}

Array convertToArray(HashTable table)
{
    Array array = calloc(sizeof(*array), 1);
    array->capacity = table->count;
    array->elements = calloc(sizeof(ArrayElement), array->capacity);
    array->count = table->count;
    for (int i = 0; i < table->capacity; i++)
    {
        Node node = table->nodes[i];
        while (node)
        {
            ArrayElement elt;
            elt.PREF = node->elt.PREF;
            elt.CHAR = node->elt.CHAR;
            elt.frequency = node->elt.frequency;
            /*if (node->elt.CODE > array->capacity)
            {
                char* n = NULL;
                *n = 5;
            }*/
            array->elements[node->elt.CODE - 1] = elt;
            node = node->next;
        }
    }
    return array;
}

HashTable convertToTable(Array array)
{
    HashTable table = makeTable();
    for (int i = 0; i < array->count; i++)
    {
        Element elt;
        elt.PREF = array->elements[i].PREF;
        elt.CHAR = array->elements[i].CHAR;
        elt.CODE = i+1;
        elt.frequency = array->elements[i].frequency;
        insertIntoTable(table, elt);
    }
    return table;
}

// for debugging: will verify if table has a code with itself as the prefix
void checkTable(HashTable table)
{
    checkArray(convertToArray(table));
}

void checkArray(Array array)
{
    for (int i = 0; i < array->count; i++)
    {
        ArrayElement elt = array->elements[i];
        if (i+1 <= elt.PREF) DIE("%s", "Invalid array");
    }
}
