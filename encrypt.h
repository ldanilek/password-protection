/**
 * Password-protects a list of files/directories
 * Usage: encrypt flags ArchiveName File1 File2 ...
 * Usage: decrypt flags ArchiveName
 *
 * Flag descriptions
 * -p    Shows password as it is typed. This allows arbitrarily long passwords.
 *       Default is to use getpass(), which doesn't display password as typed,
 *       but truncates input to length _PASSWORD_LEN (currently 128 characters)
 * -q    Quiet mode. Prints no progress output and only prints fatal errors
 *
 * Flags may be separated or condensed, so -pq and -p -q are both valid
 * 
 * the following filenames must be unused (files will be overwritten),
 * where ArchiveName is the command line argument:
 * ArchiveName.far
 * ArchiveName.lzw
 * ArchiveName
 * On decrypt, all files to extract will be overwritten
 *
 * ArchiveName may not begin with a hyphen, but it may be any writable path
 * Therefore ./-name is a valid workaround
 * Files listed in the command line are paths to files or directories
 *
 * General procedure:
 * Note that every file is prefixed by some metadata
 * Request password string from stdin
 * Create ArchiveName.far, a single file containing listed files and directories
 *     metadata: 0 byte
 * Create ArchiveName.lzw by performing LZW compression on ArchiveName.far
 *     metadata: nonzero byte
 * If ArchiveName.lzw is bigger, ignore it and use ArchiveName.far instead
 *     In decryption, run lzw decompression iff the first byte is nonzero
 * Create ArchiveName by running RSA encryption
 *     metadata: hash of password string using the DES-based crypt function
 *
 * All RSA keys are hard-coded into the source code of encrypt, so to maintain
 * security you should compile, then encrypt the source file encrypt.c
 * If portability isn't a problem, you can remove encrypt.c after compiling
 */

// Write message to stderr using format FORMAT
#define WARN(format,...) fprintf (stderr, format "\n", __VA_ARGS__)

// Write message to stderr using format FORMAT and exit.
#define DIE(format,...)  WARN(format,__VA_ARGS__), exit (EXIT_FAILURE)

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define _XOPEN_SOURCE
#include <unistd.h>

