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
 *       Whether using this flag or not, Terminal's "Secure Keyboard Entry" is a
 *       useful feature to block keyloggers and other apps.
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
 * -i    Insecure mode. Does not prompt for password, instead using the default
 *       password DEFAULT_PASSWORD defined in keys.h. Overrides -p flag.
 *
 * -c    Compression/Decompression only. Same as using lzwcompress and
 *       lzwdecompress when compiled with make compression
 *
 * Flags may be separated or condensed, so -pq and -pv -q are both valid
 * 
 * The following filenames must be unused
 * (files will be overwritten if writable),
 * where ArchiveName is the command line argument,
 * and File is any command line argument after the ArchiveName:
 * ArchiveName.far (only in series mode)
 * ArchiveName (only in encode, in decode this file is needed)
 * ArchiveName.lzw (only in encode)
 * File (only in decode, in encode this file is needed)
 *
 * ArchiveName may not begin with a hyphen, but it may be any writable path
 * Therefore ./-name is a valid workaround
 * If ArchiveName is -, archive is read from stdin or written to stdout
 *
 * Files listed in the command line are paths to files or directories
 * Files and subfiles with a .lzw extension will be ignored
 *
 * General procedure:
 * Note that every file is prefixed by some metadata
 * Request password string from /dev/tty (similar to stdin)
 * Create ArchiveName.far, a single file containing listed files and directories
 * With data from files compressed using LZW compression
 *     metadata before each file: 0 byte if uncompressed, nonzero byte otherwise
 * Create ArchiveName by running RSA encryption
 *     metadata: hash of password string and salt using the SHA1 hash function
 *
 * All RSA keys are hard-coded into the source code of rsa.c, so to maintain
 * security you should compile, then encrypt the source file keys.h
 * If portability isn't a problem, you can remove keys.h after compiling,
 * and run make clean to remove rsa.o
 */

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "bitcode.h"
#include <stdio.h>

// if MAC is zero,
// struct stat must have member st_atime and company
// if MAC is nonzero,
// struct stat must have member st_atimespec and company
#define MAC 1

#define DEFAULT_PASSWORD "password"

extern bool quiet;
extern bool verbose;
extern bool removeOriginal;
extern bool series;

#define EXIT_FAILURE 1

// use for major status changes and minor errors
#define STATUS(format,...) if(!quiet)fprintf(stderr,format "\n",__VA_ARGS__)
// use for minor progress reports
#define PROGRESS(format,...) if(verbose)fprintf(stderr,format "\n",__VA_ARGS__)

// no newline, string literal
#define PROGRESS_PART(format) if(verbose)fprintf(stderr,format)

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

#define STAT(x) (WIFEXITED(x) ? WEXITSTATUS(x) : 128+WTERMSIG(x))

#endif