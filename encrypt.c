#define _XOPEN_SOURCE
#include "encrypt.h"
#include "far.h"
#include "lzw.h"
#ifdef ENCRYPT
#include "rsa.h"
#endif
#include <libgen.h>
#include <ctype.h>

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

// only owner has permission for the archive
// it can be read or (over)written
#define ARCHIVE_PERMISSION (0600)

// doesn't have to worry about encoding, since archive() takes care of that
// uses a child process to archive/encode and encrypts in the parent
void protect(char* password, char* archiveName, char* archiveLZW,
    int nodeC, char** nodes)
{
    int newFile = open(archiveName,O_WRONLY|O_CREAT|O_TRUNC,ARCHIVE_PERMISSION);
    if (newFile < 0) SYS_DIE("open");
    
#ifdef ENCRYPT
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
#else
    archive(newFile, archiveLZW, nodeC, nodes);
#endif

    if (close(newFile)) SYS_ERROR("close");
}

// extract() takes care of decoding
// use child process for decrypting, extract in parent
void unprotect(char* password, char* archiveName)
{
    int archiveFile = open(archiveName, O_RDONLY);
    if (archiveFile < 0) SYS_DIE("open");

#ifdef ENCRYPT
    int decryptToExtractPipe[2];
    if (pipe(decryptToExtractPipe)) SYS_DIE("pipe");

    pid_t decryptProcess = fork();
    if (decryptProcess < 0) SYS_DIE("fork");
    if (decryptProcess == 0)
    {
        if (close(decryptToExtractPipe[0])) SYS_DIE("close");

        decryptRSA(password, archiveFile, decryptToExtractPipe[1]);

        exit(0);
    }
    if (close(decryptToExtractPipe[1])) SYS_ERROR("close");
#else
    // if not decrypting, just pass archiveFile in to extract
    extract(archiveFile);
#endif
    if (close(archiveFile)) SYS_ERROR("close");

#ifdef ENCRYPT
    extract(decryptToExtractPipe[0]);

    if (close(decryptToExtractPipe[0])) SYS_ERROR("close");

    // reap the zombie
    int status = 0;
    if (waitpid(decryptProcess, &status, 0) < 0) SYS_DIE("waitpid");
    if (status) DIE("decryptProcess exit status %d", STAT(status));
#endif

    if (removeOriginal && remove(archiveName)) SYS_ERROR("remove");
}

// in sequence. significantly slower, but progress statements make more sense
void protectS(char* password, char* archiveName, char* archiveFar,
    char* archiveLZW, int nodeC, char** nodes)
{
    FILE* arch = fopen(archiveName, "w");
    if (!arch) SYS_DIE("fopen");
#ifdef ENCRYPT
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
#else
    archive(fileno(arch), archiveLZW, nodeC, nodes);
#endif
    if (fclose(arch)) SYS_ERROR("fclose");
}

void unprotectS(char* password, char* archiveName, char* archiveFar)
{
    FILE* arch = fopen(archiveName, "r");
    if (!arch) SYS_DIE("fopen");

#ifdef ENCRYPT
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
#else
    // extract from arch
    extract(fileno(arch));
#endif

    if (fclose(arch)) SYS_ERROR("fclose");
    if (removeOriginal && remove(archiveName)) SYS_ERROR("remove");
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
#if MAC
    bool showPassword = false;
#else
    bool showPassword = true;
#endif
#endif
    bool series = false;
    int flagIndex = 1;
    while (flagIndex < argc && argv[flagIndex][0] == '-')
    {
        char* flag = argv[flagIndex]+1;
        int flagCount = strlen(flag);
        for (int fIndex = 0; fIndex < flagCount; fIndex++)
        {
            if (flag[fIndex] == 'r') removeOriginal = true;
            else if (flag[fIndex] == 'q') quiet = true, verbose = false;
            else if (flag[fIndex] == 'v') verbose = true, quiet = false;
#ifdef ENCRYPT
            else if (flag[fIndex] == 'p') showPassword = true;
#endif
            else if (flag[fIndex] == 's') series = true;
            else DIE("Invalid flag %c", flag[fIndex]);
        }
        flagIndex++;
    }

    if (decrypt && argc-flagIndex < 1) DIE("Invalid decrypt argc: %d", argc);
    if (!decrypt && argc-flagIndex < 2) DIE("Invalid encrypt argc: %d", argc);

    // take password as input
    char* password = "";
#ifdef ENCRYPT
#if MAC
    if (showPassword)
    {
#endif
        int capacity = 5;
        password = calloc(capacity, sizeof(char));
        int count = 0;
        int c;
        fprintf(stderr, PASSWORD_PROMPT);
        while (isprint(c = getchar()))
        {
            if (count+1 >= capacity)
            {
                capacity*=2;
                password = realloc(password, capacity*sizeof(char));
            }
            password[count++] = c;
        }
        password[count] = '\0';
#if MAC
    }
    else
    {
        password = getpass(PASSWORD_PROMPT);
    }
#endif
#endif

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
    if (showPassword) free(password);
#endif
}







