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

#define PASSWORD_PROMPT "Input password: "

// quiet mode
bool quiet = false;
// verbose mode
bool verbose = false;
// remove original files (listed files on encrypt, archive on decrypt)
bool removeOriginal = false;

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
    bool showPassword = false;
#endif
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
            else DIE("Invalid flag %c", flag[fIndex]);
        }
        flagIndex++;
    }

    if (decrypt && argc-flagIndex < 1) DIE("Invalid decrypt argc: %d", argc);
    if (!decrypt && argc-flagIndex < 2) DIE("Invalid encrypt argc: %d", argc);

    char* archiveName = argv[flagIndex];
    int archiveNameLen = strlen(archiveName);

#ifdef ENCRYPT
    // take password as input
    char* password;
    if (showPassword)
    {
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
    }
    else
    {
        password = getpass(PASSWORD_PROMPT);
    }
#endif

    // make room for .far with null terminator
    char* archiveFar = calloc(archiveNameLen + 5, sizeof(char));
    sprintf(archiveFar, "%s.far", archiveName);

    char* archiveLZW = calloc(archiveNameLen + 5, sizeof(char));
    sprintf(archiveLZW, "%s.lzw", archiveName);

    if (decrypt)
    {
#ifdef ENCRYPT
        decryptRSA(password, archiveName, archiveLZW);
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
        decode(archiveLZW, archiveFar);
        extract(archiveFar);
    }
    else
    {
        archive(archiveFar, argc-flagIndex-1, argv+flagIndex+1);
        encode(archiveFar, archiveLZW);
#ifdef ENCRYPT
        encryptRSA(password, archiveLZW, archiveName);
#else
        if (rename(archiveLZW, archiveName)) SYS_DIE("rename");
#endif
    }
    
#ifdef ENCRYPT
    if (showPassword) free(password);
#endif
    free(archiveFar);
    free(archiveLZW);
}







