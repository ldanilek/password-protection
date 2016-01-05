// code.c                                         Stan Eisenstat (09/23/09)
//
// Implementation of putBits/getBits described in code.h

#include <stdio.h>
#include <stdlib.h>
#include "bitcode.h"
#include "encrypt.h"
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// Information shared by putBits() and flushBits()

void fdputc(char c, int fd)
{
    if (write(fd, &c, 1) < 1) SYS_DIE("write");
}

int fdgetc(int fd)
{
    unsigned char character;
    int readBytes;
    if ((readBytes = read(fd, &character, 1)) < 0) SYS_DIE("read");
    if (readBytes == 0) return EOF;
    return character;
}

bool rdhang(int fd, void* bytes, int len)
{
    if (len == 0) return true;
    int lengthRead = 0;
    int totalRead = 0;
    while (len > 0 && (lengthRead = read(fd, bytes + totalRead, len)) > 0)
    {
        len -= lengthRead;
        totalRead += lengthRead;
    }
    if (lengthRead < 0) SYS_DIE("read"); // read had an error
    if (lengthRead == 0 && len > 0 && totalRead > 0)
    {
        // hit EOF; read in some but not all
        DIE("%d spare bytes", totalRead);
    }
    return len == 0; // return whether everything was read
}

int rdhangPartial(int fd, void* bytes, int len)
{
    if (len == 0) return true;
    int lengthRead = 0;
    int totalRead = 0;
    while (len > 0 && (lengthRead = read(fd, bytes + totalRead, len)) > 0)
    {
        len -= lengthRead;
        totalRead += lengthRead;
    }
    if (lengthRead < 0) SYS_DIE("read"); // read had an error
    return totalRead; // return whether everything was read
}

// == PUTBITS MODULE =======================================================

// Write CODE (NBITS bits) to standard output
void putBits (int nBits, int code, int fd, BitCache* cache)
{
    unsigned int c;

    if (nBits > (sizeof(int)-1) * CHAR_BIT)
    exit (fprintf (stderr, "putBits: nBits = %d too large\n", nBits));

    code &= (1 << nBits) - 1;                   // Clear high-order bits
    cache->nExtra += nBits;                     // Add new bits to extraBits
    cache->extraBits = (cache->extraBits << nBits) | code;
    while (cache->nExtra >= CHAR_BIT) {         // Output any whole chars
        cache->nExtra -= CHAR_BIT;              //  and save remaining bits
        c = cache->extraBits >> cache->nExtra;
        fdputc(c, fd);
        cache->extraBits ^= c << cache->nExtra;
    }
}

// Flush remaining bits to standard output
void flushBits (int fd, BitCache* cache)
{
    if (cache->nExtra != 0)
        fdputc(cache->extraBits << (CHAR_BIT - cache->nExtra), fd);
}

// == GETBITS MODULE =======================================================

// Return next code (#bits = NBITS) from input stream or EOF on end-of-file
int getBits (int nBits, int fd, BitCache* cache)
{
    int c;
                                          
    if (nBits > (sizeof(cache->extraBits)-1) * CHAR_BIT)
    exit (fprintf (stderr, "getBits: nBits = %d too large\n", nBits));

    // Read enough new bytes to have at least nBits bits to extract code
    while (cache->nExtra < nBits) {
        // Return EOF on end-of-file
        if ((c = fdgetc(fd)) == EOF) return EOF;
        cache->nExtra += CHAR_BIT;
        cache->extraBits = (cache->extraBits << CHAR_BIT) | c;
    }
    cache->nExtra -= nBits;                            // Return nBits bits
    c = cache->extraBits >> cache->nExtra;
    cache->extraBits ^= c << cache->nExtra;            // Save remainder
    return c;
}
