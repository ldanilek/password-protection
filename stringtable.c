
#include "stringtable.h"
#include <stdlib.h>

int hash(int PREF, unsigned char CHAR)
{
    // use recommended hash function
    return (PREF << CHAR_BIT) ^ CHAR;
}

HashTable makeTable(void)
{
    HashTable table = calloc(sizeof(*table), 1);
    table->capacity = 3;
    table->nodes = calloc(sizeof(Node), table->capacity);
    return table;
}

void freeTable(HashTable table)
{
    for (int i = 0; i < table->capacity; i++)
    {
        Node node = table->nodes[i];
        while (node)
        {
            Node next = node->next;
            free(node);
            node = next;
        }
    }
    free(table->nodes);
    free(table);
}

void growTable(HashTable table)
{
    int oldCapacity = table->capacity;
    Node* oldNodes = table->nodes;
    table->capacity = 2*oldCapacity + 1; // should be odd for performance
    table->nodes = calloc(sizeof(Node), table->capacity);
    table->count = 0;
    for (int i = 0; i < oldCapacity; i++)
    {
        Node node = oldNodes[i];
        while (node)
        {
            insertIntoTable(table, node->elt);
            Node next = node->next;
            free(node);
            node = next;
        }
    }
    free(oldNodes);
}

void insertIntoTable(HashTable table, Element elt)
{
    // max load factor of 1
    if (++table->count > table->capacity)
    {
        growTable(table);
        table->count++;
    }
    int bucket = hash(elt.PREF, elt.CHAR) % table->capacity;
    Node newNode = calloc(sizeof(*newNode), 1);
    newNode->elt = elt;
    newNode->next = table->nodes[bucket];
    table->nodes[bucket] = newNode;
}

Node searchTable(HashTable table, int PREF, char CHAR)
{
    int bucket = hash(PREF, CHAR) % table->capacity;
    Node node = table->nodes[bucket];
    while (node)
    {
        if (node->elt.PREF == PREF && node->elt.CHAR == CHAR)
        {
            return node;
        }
        node = node->next;
    }
    return NULL;
}

HashTable copyTable(HashTable table)
{
    HashTable new = makeTable();
    for (int i = 0; i < table->capacity; i++)
    {
        Node node = table->nodes[i];
        while (node)
        {
            insertIntoTable(new, node->elt);
            node = node->next;
        }
    }
    return new;
}


