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

void protect(char* password, char* archiveName, int nodeC, char** nodes)
{
    int archiveToEncodePipe[2];
    if (pipe(archiveToEncodePipe)) SYS_DIE("pipe");

    pid_t archiveProcess = fork();
    if (archiveProcess < 0) SYS_DIE("fork");
    if (archiveProcess == 0)
    {
        if (close(archiveToEncodePipe[0])) SYS_DIE("close");
        archive(archiveToEncodePipe[1], nodeC, nodes);
        
        exit(0);
    }
    // parent process
    if (close(archiveToEncodePipe[1])) SYS_DIE("close");

    int newFile = open(archiveName, O_WRONLY|O_CREAT|O_TRUNC);
    if (newFile < 0) SYS_DIE("open");

    int encodeToEncryptPipe[2];
#ifdef ENCRYPT
    if (pipe(encodeToEncryptPipe)) SYS_DIE("pipe");
#else
    encodeToEncryptPipe[1] = newFile;
#endif

    pid_t encodeProcess = fork();
    if (encodeProcess < 0) SYS_DIE("fork");
    if (encodeProcess == 0)
    {
#ifdef ENCRYPT
        if (close(encodeToEncryptPipe[0])) SYS_DIE("close");
#endif
        encode(archiveToEncodePipe[0], encodeToEncryptPipe[1]);

        exit(0);
    }
    // parent process
    if (close(archiveToEncodePipe[0])) SYS_DIE("close");
    if (close(encodeToEncryptPipe[1])) SYS_DIE("close");

#ifdef ENCRYPT
    encryptRSA(password, encodeToEncryptPipe[0], newFile);
    if (close(encodeToEncryptPipe[0])) SYS_DIE("close");
    if (close(newFile)) SYS_DIE("close");
#endif
    // wait for child processes to end
    // (if encrypt ran, they've already ended, but should still reap them)
    int archiveStatus = 0;
    if (waitpid(archiveProcess, &archiveStatus, 0) < 0) SYS_DIE("waitpid");
    int encodeStatus = 0;
    if (waitpid(encodeProcess, &encodeStatus, 0) < 0) SYS_DIE("waitpid");

    if (encodeStatus || archiveStatus)
    {
        // something got fucked up. very likely encodeStatus is UNCOMPRESSABLE,
        // but even if it isn't just treat it like it is.
        newFile = open(archiveName, O_WRONLY|O_CREAT|O_TRUNC);
        if (newFile < 0) SYS_DIE("open");

#ifdef ENCRYPT
        int archiveToEncryptPipe[2];
        if (pipe(archiveToEncryptPipe)) SYS_DIE("pipe");

        archiveProcess = fork();
        if (archiveProcess < 0) SYS_DIE("fork");
        if (archiveProcess == 0)
        {
            if (close(archiveToEncryptPipe[0])) SYS_DIE("close");
            archive(archiveToEncryptPipe[1], nodeC, nodes);
            exit(0);
        }
        if (close(archiveToEncryptPipe[1])) SYS_DIE("close");
        encryptRSA(password, archiveToEncryptPipe[0], newFile);
        if (close(archiveToEncryptPipe[0])) SYS_DIE("close");
        archiveStatus = 0;
        if (waitpid(archiveProcess, &archiveStatus, 0) < 0) SYS_DIE("waitpid");
#else
        archive(newFile, nodeC, nodes);
#endif

        if (close(newFile)) SYS_DIE("close");
    }
    if (removeOriginal && remove(archiveName)) SYS_ERROR("remove");
}

void unprotect(char* password, char* archiveName)
{
    int archiveFile = open(archiveName, O_RDONLY);
    if (archiveFile < 0) SYS_DIE("open");

    int decryptToDecodePipe[2];
#ifdef ENCRYPT
    if (pipe(decryptToDecodePipe)) SYS_DIE("pipe");

    pid_t decryptProcess = fork();
    if (decryptProcess < 0) SYS_DIE("fork");
    if (decryptProcess == 0)
    {
        if (close(decryptToDecodePipe[0])) SYS_DIE("close");

        decryptRSA(password, archiveFile, decryptToDecodePipe[1]);

        exit(0);
    }
    if (close(archiveFile)) SYS_DIE("close");
    if (close(decryptToDecodePipe[1])) SYS_DIE("close");
#else
    // if not decrypting, just pass archiveFile in to decode
    decryptToDecodePipe[0] = archiveFile;
#endif

    int decodeToExtractPipe[2];
    if (pipe(decodeToExtractPipe)) SYS_DIE("pipe");

    pid_t decodeProcess = fork();
    if (decodeProcess < 0) SYS_DIE("fork");
    if (decodeProcess == 0)
    {
        if (close(decodeToExtractPipe[0])) SYS_DIE("close");

        decode(decryptToDecodePipe[0], decodeToExtractPipe[1]);

        exit(0);
    }
    if (close(decryptToDecodePipe[0])) SYS_DIE("close");
    if (close(decodeToExtractPipe[1])) SYS_DIE("close");

    extract(decodeToExtractPipe[0]);

    if (close(decodeToExtractPipe[0])) SYS_DIE("close");

    // reap the zombies
    int status = 0;
#ifdef ENCRYPT
    if (waitpid(decryptProcess, &status, 0) < 0) SYS_DIE("waitpid");
    if (status) DIE("decryptProcess exit status %d", STAT(status));
#endif
    if (waitpid(decodeProcess, &status, 0) < 0) SYS_DIE("waitpid");
    if (status) DIE("decodeProcess exit status %d", STAT(status));
}

// in sequence. significantly slower, but progress statements make more sense
void protectS(char* password, char* archiveName, char* archiveFar,
    char* archiveLZW, int nodeC, char** nodes)
{
    FILE* far = fopen(archiveFar, "w");
    archive(fileno(far), nodeC, nodes);
    fclose(far);
    far = fopen(archiveFar, "r");
    FILE* lzw = fopen(archiveLZW, "w");

    // this might exit(UNCOMPRESSABLE), so do in subprocess
    pid_t encodeProcess = fork();
    if (encodeProcess < 0) SYS_DIE("fork");
    if (encodeProcess == 0)
    {
        encode(fileno(far), fileno(lzw));
        exit(0);
    }
    int status = 0;
    if (waitpid(encodeProcess, &status, 0) < 0) SYS_DIE("waitpid");
    fclose(far);
    fclose(lzw);
    if (status)
    {
        if (rename(archiveFar, archiveLZW)) SYS_DIE("rename");
    }
    else if (remove(archiveFar)) SYS_ERROR("remove");
    
#ifdef ENCRYPT
    lzw = fopen(archiveLZW, "r");
    FILE* arch = fopen(archiveName, "w");
    encryptRSA(password, fileno(lzw), fileno(arch));
    fclose(arch);
    fclose(lzw);
    if (remove(archiveLZW)) SYS_ERROR("remove");
#else
    if (rename(archiveLZW, archiveName)) SYS_DIE("rename");
#endif
}

void unprotectS(char* password, char* archiveName, char* archiveFar,
    char* archiveLZW)
{
#ifdef ENCRYPT
    FILE* arch = fopen(archiveName, "r");
    FILE* lzw = fopen(archiveLZW, "w");
    decryptRSA(password, fileno(arch), fileno(lzw));
    fclose(arch);
    fclose(lzw);
#else
    if (removeOriginal)
    {
        if (rename(archiveName, archiveLZW)) SYS_DIE("rename");
    }
    else
    {
        // copy it over
        FILE* archive = fopen(archiveName, "r");
        FILE* lzw = fopen(archiveLZW, "w");
        if (!archive) SYS_DIE("fopen");
        if (!lzw) SYS_DIE("fopen");
        int c;
        while ((c = fgetc(archive)) != EOF) fputc(c, lzw);
        if (fclose(archive)) SYS_ERROR("fclose");
        if (fclose(lzw)) SYS_ERROR("fclose");
    }
#endif
    lzw = fopen(archiveLZW, "r");
    FILE* far = fopen(archiveFar, "w");
    decode(fileno(lzw), fileno(far));
    fclose(lzw);
    fclose(far);
    far = fopen(archiveFar, "r");
    extract(fileno(far));
    fclose(far);
}


int main(int argc, char** argv)
{
    // find which program to run
    bool decrypt;
    char* progName = basename(argv[0]);
    if (!strcmp(progName, "encrypt") || !strcmp(progName, "compress"))
    {
        decrypt = false;
    }
    else if (!strcmp(progName, "decrypt") || !strcmp(progName, "decompress"))
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
    char* password;
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

    if (series)
    {
        int archiveNameLen = strlen(archiveName);
        // make room for .far with null terminator
        char* archiveFar = calloc(archiveNameLen + 5, sizeof(char));
        sprintf(archiveFar, "%s.far", archiveName);

        char* archiveLZW = calloc(archiveNameLen + 5, sizeof(char));
        sprintf(archiveLZW, "%s.lzw", archiveName);
        if (decrypt)
        {
            unprotectS(password, archiveName, archiveFar, archiveLZW);
        }
        else
        {
            protectS(password, archiveName, archiveFar, archiveLZW,
                argc-flagIndex-1, argv+flagIndex+1);
        }
        free(archiveFar);
        free(archiveLZW);
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
            protect(password, archiveName, argc-flagIndex-1, argv+flagIndex+1);
        }
    }

    
    
#ifdef ENCRYPT
    if (showPassword) free(password);
#endif
}







