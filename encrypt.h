/**
 * Password-protects a list of files/directories
 * Usage: encrypt flags ArchiveName File1 File2 ...
 * Usage: decrypt flags ArchiveName
 *
 * Flag descriptions
 * -p    Shows password as it is typed. This allows arbitrarily long passwords.
 *       Default is to use getpass(), which doesn't display password as typed,
 *       but truncates input to length _PASSWORD_LEN (currently 128 characters).
 *       With this flag, allows printable characters as determined by isprint().
 *       Password is terminated by first non-printing character (newline or EOF)
 *
 * -q    Quiet mode. Only prints fatal errors.
 *
 * -v    Verbose mode. Prints extensive progress report.
 *       By default, prints basic progress report.
 *       Mutually exclusive with -q (last found is used)
 *
 * -r    Remove original. On encrypt, this removes files and directories as it
 *       archives them. On decrypt, this removes the archive file (if 
 *       password is correct).
 *
 * -s    Series mode. Executes the three parts of the program in sequence.
 *       Uses fewer processes and file descriptors. Default is parallel mode,
 *       which is almost always faster but status logs are more confusing.
 *
 * Flags may be separated or condensed, so -pq and -pv -q are both valid
 * 
 * the following filenames must be unused (files will be overwritten),
 * where ArchiveName is the command line argument:
 * ArchiveName.far
 * ArchiveName.lzw
 * ArchiveName
 * On decrypt, all files to extract will be overwritten,
 * and ArchiveName is required to exist and be readable
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
 *     metadata: hash of password string using the SHA1 hash function
 *
 * All RSA keys are hard-coded into the source code of encrypt, so to maintain
 * security you should compile, then encrypt the source file encrypt.c
 * If portability isn't a problem, you can remove encrypt.c after compiling
 */

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdbool.h>
#include <stdio.h>

#define MAC 0

extern bool quiet;
extern bool verbose;
extern bool removeOriginal;

#define EXIT_FAILURE 1

// use for major status changes and minor errors
#define STATUS(format,...) if(!quiet)fprintf(stderr,format "\n",__VA_ARGS__)
// use for minor progress reports
#define PROGRESS(format,...) if(verbose)fprintf(stderr,format "\n",__VA_ARGS__)

// no newline, string literal, and fflushes
#define PROGRESS_PART(format) if(verbose)fprintf(stderr,format),fflush(stdout)

// Write message to stderr using format FORMAT
#define WARN(format,...) fprintf (stderr, format "\n", __VA_ARGS__)

// Write message to stderr using format FORMAT and exit.
#define DIE(format,...)  WARN(format,__VA_ARGS__), exit (EXIT_FAILURE)

// call after system call fails to print error associated with errno
#define SYS_ERROR(name) if(!quiet)perror(name)
// system error followed by return from current function
#define SYS_ERR_DONE(name) {SYS_ERROR(name);return;}
// fatal system error
#define SYS_DIE(name) perror(name),exit(EXIT_FAILURE)

#endif