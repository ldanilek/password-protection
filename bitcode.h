// code.h                                         Stan Eisenstat (09/23/08)
//
// Interface to putBits/getBits

#include <limits.h>
#include <stdio.h>
#include <stdbool.h>

// Write code (#bits = nBits) to standard output.
// [Since bits are written as CHAR_BIT-bit characters, any extra bits are
//  saved, so that final call must be followed by call to flushBits().]
void putBits (int nBits, int code, int fd);

// Flush any extra bits to standard output
void flushBits (int fd);

// Return next code (#bits = nBits) from standard input (EOF on end-of-file)
int getBits (int nBits, int fd);

// Clear the bit cache to start writing to new file next time
// done automatically on flushBits()
void clearPutBits(void);

// clear the bit cache to start reading from a new file next time
// done automatically when getBits() hits EOF
void clearGetBits(void);

// for getting and putting characters from file descriptors
// does not cache, so is slow
void fdputc(char c, int fd);
int fdgetc(int fd);

// version of read that works how I want it to work
// returns bool of whether it read in the bytes. 
// all-or-nothing read. if only partially read before EOF, DIEs
// useful when reading from a fixed-format file, so I know what size the data
// should be
bool rdhang(int fd, void* bytes, int len);

// same as above but allows partial reads and returns the number of bytes read
// different from read() because will only stop at EOF (not end of pipe)
int rdhangPartial(int fd, void* bytes, int len);
