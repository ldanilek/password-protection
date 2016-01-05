#define _XOPEN_SOURCE
#include "encrypt.h"
#include "far.h"
#include "lzw.h"
#ifdef ENCRYPT
#include "rsa.h"
#endif
#include <libgen.h>
#include <ctype.h>
#include "keys.h"
#if MAC
#else
#include <termios.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#define PASSWORD_PROMPT "Input password: "

#define STAT(x) (WIFEXITED(x) ? WEXITSTATUS(x) : 128+WTERMSIG(x))

// quiet mode
bool quiet = false;
// verbose mode
bool verbose = false;
// remove original files (listed files on encrypt, archive on decrypt)
bool removeOriginal = false;
// just compress
bool compressionOnly = false;

// only owner has permission for the archive
// it can be read or (over)written
#define ARCHIVE_PERMISSION (0600)

// doesn't have to worry about encoding, since archive() takes care of that
// uses a child process to archive/encode and encrypts in the parent
void protect(char* password, char* archiveName, char* archiveLZW,
    int nodeC, char** nodes)
{
    int newFile = STDOUT_FILENO;
    if (strcmp(archiveName, "-"))
        newFile = open(archiveName,O_WRONLY|O_CREAT|O_TRUNC,ARCHIVE_PERMISSION);
    if (newFile < 0) SYS_DIE("open");
    
#ifdef ENCRYPT
if (compressionOnly)
{
    archive(newFile, archiveLZW, nodeC, nodes);
}
else
{
    int archiveToEncryptPipe[2];
    if (pipe(archiveToEncryptPipe)) SYS_DIE("pipe");

    pid_t archiveProcess = fork();
    if (archiveProcess < 0) SYS_DIE("fork");
    if (archiveProcess == 0)
    {
        if (close(archiveToEncryptPipe[0])) SYS_DIE("close");
        archive(archiveToEncryptPipe[1], archiveLZW, nodeC, nodes);
        
        exit(0);
    }
    // parent process
    if (close(archiveToEncryptPipe[1])) SYS_DIE("close");

    encryptRSA(password, archiveToEncryptPipe[0], newFile);
    if (close(archiveToEncryptPipe[0])) SYS_ERROR("close");

    // wait for child process to end (reap it)
    int archiveStatus = 0;
    if (waitpid(archiveProcess, &archiveStatus, 0) < 0) SYS_DIE("waitpid");
    if (archiveStatus)DIE("Archive exited with status %d", STAT(archiveStatus));
}
#else
    archive(newFile, archiveLZW, nodeC, nodes);
#endif

    if (close(newFile)) SYS_ERROR("close");
}

// extract() takes care of decoding
// use child process for decrypting, extract in parent
void unprotect(char* password, char* archiveName)
{
    int archiveFile = STDIN_FILENO;
    if (strcmp(archiveName, "-"))
        archiveFile = open(archiveName, O_RDONLY);
    if (archiveFile < 0) SYS_DIE("open");

#ifdef ENCRYPT
    int decryptToExtractPipe[2];
    pid_t decryptProcess;
if (compressionOnly) {
    extract(archiveFile);
}
else
{
    if (pipe(decryptToExtractPipe)) SYS_DIE("pipe");

    decryptProcess = fork();
    if (decryptProcess < 0) SYS_DIE("fork");
    if (decryptProcess == 0)
    {
        if (close(decryptToExtractPipe[0])) SYS_DIE("close");

        decryptRSA(password, archiveFile, decryptToExtractPipe[1]);

        exit(0);
    }
    if (close(decryptToExtractPipe[1])) SYS_ERROR("close");
}
#else
    // if not decrypting, just pass archiveFile in to extract
    extract(archiveFile);
#endif
    if (close(archiveFile)) SYS_ERROR("close");

#ifdef ENCRYPT
if (!compressionOnly) {
    extract(decryptToExtractPipe[0]);

    if (close(decryptToExtractPipe[0])) SYS_ERROR("close");

    // reap the zombie
    int status = 0;
    if (waitpid(decryptProcess, &status, 0) < 0) SYS_DIE("waitpid");
    if (status) DIE("decryptProcess exit status %d", STAT(status));
}
#endif

    if (strcmp(archiveName, "-") && removeOriginal && remove(archiveName))
        SYS_ERROR("remove");
}

// in sequence. significantly slower, but progress statements make more sense
void protectS(char* password, char* archiveName, char* archiveFar,
    char* archiveLZW, int nodeC, char** nodes)
{
    FILE* arch = stdout;
    if (strcmp(archiveName, "-"))
        arch = fopen(archiveName, "w");
    if (!arch) SYS_DIE("fopen");
#ifdef ENCRYPT
if (compressionOnly)
{
    archive(fileno(arch), archiveLZW, nodeC, nodes);
}
else
{
    // archive into far
    FILE* far = fopen(archiveFar, "w");
    if (!far) SYS_DIE("fopen");
    archive(fileno(far), archiveLZW, nodeC, nodes);
    if (fclose(far)) SYS_ERROR("fclose");
    // encrypt from far to archive
    far = fopen(archiveFar, "r");
    if (!far) SYS_DIE("fopen");
    encryptRSA(password, fileno(far), fileno(arch));
    if (fclose(far)) SYS_ERROR("fclose");
    if (remove(archiveFar)) SYS_ERROR("remove");
}
#else
    archive(fileno(arch), archiveLZW, nodeC, nodes);
#endif
    if (fclose(arch)) SYS_ERROR("fclose");
}

void unprotectS(char* password, char* archiveName, char* archiveFar)
{
    FILE* arch = stdin;
    if (strcmp(archiveName, "-"))
        arch = fopen(archiveName, "r");
    if (!arch) SYS_DIE("fopen");

#ifdef ENCRYPT
if (compressionOnly)
{
    extract(fileno(arch));
}
else
{
    // decrypt into far
    FILE* far = fopen(archiveFar, "w");
    if (!far) SYS_DIE("fopen");
    decryptRSA(password, fileno(arch), fileno(far));
    if (fclose(far)) SYS_ERROR("fclose");
    // extract from far
    far = fopen(archiveFar, "r");
    if (!far) SYS_DIE("fopen");
    extract(fileno(far));
    if (fclose(far)) SYS_ERROR("fclose");
    if (remove(archiveFar)) SYS_ERROR("remove");
}
#else
    // extract from arch
    extract(fileno(arch));
#endif

    if (fclose(arch)) SYS_ERROR("fclose");
    if (removeOriginal && remove(archiveName)) SYS_ERROR("remove");
}

#define USAGE_FORMAT "Usage:\n%s [options] ArchiveName File1 File2 ...\n"

void printFlagsInfo(char* flags, bool decrypt)
{
    int len = strlen(flags);
    for (int i = 0; i < len; i++)
    {
        char f = flags[i];
        char* d;
        switch (f)
        {
            case 'v':
            {d = "Verbose mode. Prints progress reports."; break;}

            case 'q':
            {d = "Quiet mode. Only prints fatal errors."; break;}

            case 'p':
            {d = "Shows password as it is typed."; break;}

            case 'r':
            {d = decrypt?"Removes archive after completion.":
                "Removes files after they are processed."; break;}

            case 'i':
            {d = "Insecure mode. Uses default password."; break;}

            case 's':
            {d = decrypt?
                "Series mode. Finishes decryption before beginning decoding.":
                "Series mode. Finishes encoding before beginning encryption.";
                break;}

            case 'c':
            {d = decrypt?
                "Decompression only. Same as lzwdecompress.":
                "Compression only. Same as lzwcompress."; break;}

            default: DIE("Invalid flag to describe: %c", f);
        }
        fprintf(stderr, "-%c: %s\n", f, d);
    }
}

// does not return, exits
void showHelpInfo(bool decrypt)
{
#ifdef ENCRYPT
    if (decrypt)
    {
        fprintf(stderr, USAGE_FORMAT, "decrypt");
    }
    else
    {
        fprintf(stderr, USAGE_FORMAT, "encrypt");
    }
    printFlagsInfo("rqvpisc", decrypt);
#else
    if (decrypt)
    {
        fprintf(stderr, USAGE_FORMAT, "lzwdecompress");
    }
    else
    {
        fprintf(stderr, USAGE_FORMAT, "lzwcompress");
    }
    printFlagsInfo("rqvs", decrypt);
#endif
    exit(0);
}

int main(int argc, char** argv)
{
    // find which program to run
    bool decrypt;
    char* progName = basename(argv[0]);
    if (!strcmp(progName, "encrypt") || !strcmp(progName, "lzwcompress"))
    {
        decrypt = false;
    }
    else if (!strcmp(progName, "decrypt") || !strcmp(progName, "lzwdecompress"))
    {
        decrypt = true;
    }
    else DIE("Invalid program name %s", argv[0]);

    // determine which flags are set
#ifdef ENCRYPT
    bool showPassword = false;
#endif
    bool series = false;
    bool defaultPassword = false;
    int flagIndex = 1;
    while (flagIndex < argc && argv[flagIndex][0] == '-')
    {
        char* flag = argv[flagIndex]+1;
        int flagCount = strlen(flag);
        if (flagCount == 0) break; // ArchiveName is "-"
        for (int fIndex = 0; fIndex < flagCount; fIndex++)
        {
            if (flag[fIndex] == 'r') removeOriginal = true;
            else if (flag[fIndex] == 'q') quiet = true, verbose = false;
            else if (flag[fIndex] == 'v') verbose = true, quiet = false;
#ifdef ENCRYPT
            else if (flag[fIndex] == 'p') showPassword = true;
            else if (flag[fIndex] == 'i') defaultPassword = true;
            else if (flag[fIndex] == 'c') compressionOnly = true;
#endif
            else if (flag[fIndex] == 's') series = true;
            else showHelpInfo(decrypt);
        }
        flagIndex++;
    }

    if (decrypt && argc-flagIndex < 1) showHelpInfo(decrypt);
    if (!decrypt && argc-flagIndex < 2) showHelpInfo(decrypt);

    // take password as input
    char* password = DEFAULT_PASSWORD;
    if (!defaultPassword)
    {
#ifdef ENCRYPT
if (!compressionOnly)
{
#if MAC
        if (showPassword)
        {
#endif
        // terminal input
        FILE* devtty = fopen("/dev/tty", "r");
        FILE* passread = devtty ? devtty : stdin;
#if MAC
#else
        struct termios TermConf;
        if (tcgetattr(fileno(passread), &TermConf)) SYS_ERROR("tcgetattr");
        if (!showPassword)
        {
            TermConf.c_lflag &= ~ECHO;
            if (tcsetattr(fileno(passread), TCSANOW, &TermConf))
                SYS_ERROR("tcsetattr");
        }
#endif
            int capacity = 5;
            password = calloc(capacity, sizeof(char));
            int count = 0;
            int c;
            fprintf(stderr, PASSWORD_PROMPT);
            
            while (isprint(c = fgetc(passread)))
            {
                if (count+1 >= capacity)
                {
                    capacity*=2;
                    password = realloc(password, capacity*sizeof(char));
                }
                password[count++] = c;
            }
#if MAC
#else
            if (!showPassword)
            {
                TermConf.c_lflag |= ECHO;
                if (tcsetattr(fileno(passread), TCSANOW, &TermConf))
                    SYS_ERROR("tcsetattr");
            }
#endif
            if (devtty && fclose(devtty)) SYS_ERROR("fclose");
            password[count] = '\0';
#if MAC
        }
        else
        {
            password = getpass(PASSWORD_PROMPT);
        }
#endif
}
#endif
    }

    char* archiveName = argv[flagIndex];

    int archiveNameLen = strlen(archiveName);

    // make room for .lzw with null terminator
    char* archiveLZW = calloc(archiveNameLen + 5, sizeof(char));
    sprintf(archiveLZW, "%s.lzw", archiveName);
    if (series)
    {
        // make room for .far with null terminator
        char* archiveFar = calloc(archiveNameLen + 5, sizeof(char));
        sprintf(archiveFar, "%s.far", archiveName);
        if (decrypt)
        {
            unprotectS(password, archiveName, archiveFar);
        }
        else
        {
            protectS(password, archiveName, archiveFar, archiveLZW,
                argc-flagIndex-1, argv+flagIndex+1);
        }
        free(archiveFar);
    }
    else
    {
        if (decrypt)
        {
            // Decrypt
            unprotect(password, archiveName);
        }
        else
        {
            // Encrypt
            protect(password, archiveName, archiveLZW,
                argc-flagIndex-1, argv+flagIndex+1);
            free(archiveLZW);
        }
    }

#ifdef ENCRYPT
if (!compressionOnly)
{
    if (!defaultPassword && showPassword) free(password);
}
#endif
}







