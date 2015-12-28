
#ifndef STRING_TABLE
#define STRING_TABLE

#include <stdint.h>
#include <limits.h>

// maximum size of a string table is 2^20
// therefore use int safely to store all
// codes, indices, counts, and capacities

typedef struct {
    // key: used for hashing
    int PREF;
    char CHAR;
    // value: not used for hashing
    int CODE;
    long frequency;
} Element;

// for hashing with chaining
struct node {
    Element elt;
    struct node* next;
};

typedef struct node* Node;

int hash(int PREF, unsigned char CHAR);

// for encode, just do a hash table
// does not support deletion or overwriting
// to prune, must create another hash table
struct hashtable {
    int count;
    int capacity;
    Node* nodes;
};

typedef struct hashtable* HashTable;

HashTable makeTable(void);
HashTable copyTable(HashTable table);

void freeTable(HashTable table);

void insertIntoTable(HashTable table, Element elt);

// returns entire Node so the frequency can be edited
// returns NULL if not found
Node searchTable(HashTable table, int PREF, char CHAR);

#endif
