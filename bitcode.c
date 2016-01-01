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
static int nExtra = 0;                  // #bits from previous byte(s)
static unsigned int extraBits = 0;      // Extra bits from previous byte(s)


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
void putBits (int nBits, int code, int fd)
{
    unsigned int c;

    if (nBits > (sizeof(int)-1) * CHAR_BIT)
    exit (fprintf (stderr, "putBits: nBits = %d too large\n", nBits));

    code &= (1 << nBits) - 1;                   // Clear high-order bits
    nExtra += nBits;                            // Add new bits to extraBits
    extraBits = (extraBits << nBits) | code;
    while (nExtra >= CHAR_BIT) {                // Output any whole chars
        nExtra -= CHAR_BIT;                     //  and save remaining bits
        c = extraBits >> nExtra;
        fdputc(c, fd);
        extraBits ^= c << nExtra;
    }
}

// Flush remaining bits to standard output
void flushBits (int fd)
{
    if (nExtra != 0)
        fdputc(extraBits << (CHAR_BIT - nExtra), fd);
    nExtra = 0;
    extraBits = 0;
}


// == GETBITS MODULE =======================================================

// Return next code (#bits = NBITS) from input stream or EOF on end-of-file
int getBits (int nBits, int fd)
{
    int c;
    static int nExtra = 0;          // #bits from previous byte(s)
    static int unsigned extra = 0;  // Extra bits from previous byte(s)
                                          
    if (nBits > (sizeof(extra)-1) * CHAR_BIT)
    exit (fprintf (stderr, "getBits: nBits = %d too large\n", nBits));

    // Read enough new bytes to have at least nBits bits to extract code
    while (nExtra < nBits) {
        if ((c = fdgetc(fd)) == EOF)
        {
            extraBits = 0;
            nExtra = 0; // reset for next file
            return EOF;                         // Return EOF on end-of-file
        }
        nExtra += CHAR_BIT;
        extra = (extra << CHAR_BIT) | c;
    }
    nExtra -= nBits;                            // Return nBits bits
    c = extra >> nExtra;
    extra ^= c << nExtra;                       // Save remainder
    return c;
}
