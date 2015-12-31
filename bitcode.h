// code.h                                         Stan Eisenstat (09/23/08)
//
// Interface to putBits/getBits

#include <limits.h>
#include <stdio.h>

// Write code (#bits = nBits) to standard output.
// [Since bits are written as CHAR_BIT-bit characters, any extra bits are
//  saved, so that final call must be followed by call to flushBits().]
void putBits (int nBits, int code, int fd);

// Flush any extra bits to standard output
void flushBits (int fd);

// Return next code (#bits = nBits) from standard input (EOF on end-of-file)
int getBits (int nBits, int fd);

// for getting and putting characters from file descriptors
// does not cache, so is slow
void fdputc(char c, int fd);
int fdgetc(int fd);