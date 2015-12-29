#include "encrypt.h"
#include "far.h"
#include "lzw.h"
#include "rsa.h"
#include <libgen.h>
#include <ctype.h>

#include <string.h>
#include <stdlib.h>
#define _XOPEN_SOURCE
#include <unistd.h>

#define PASSWORD_PROMPT "Input password: "

// quiet mode
bool quiet = false;
// verbose mode
bool verbose = false;

int main(int argc, char** argv)
{
    // find which program to run
    bool decrypt;
    char* programToRun = basename(argv[0]);
    if (strcmp(programToRun, "encrypt") == 0)
    {
        decrypt = false;
    }
    else if (strcmp(programToRun, "decrypt") == 0)
    {
        decrypt = true;
    }
    else DIE("Invalid program name %s", argv[0]);

    // determine which flags are set
    bool showPassword = false;
    int flagIndex = 1;
    while (flagIndex < argc && argv[flagIndex][0] == '-')
    {
        char* flag = argv[flagIndex]+1;
        int flagCount = strlen(flag);
        for (int fIndex = 0; fIndex < flagCount; fIndex++)
        {
            if (flag[fIndex] == 'p') showPassword = true;
            else if (flag[fIndex] == 'q') quiet = true, verbose = false;
            else if (flag[fIndex] == 'v') verbose = true, quiet = false;
            else DIE("Invalid flag %c", flag[fIndex]);
        }
        flagIndex++;
    }

    if (decrypt && argc-flagIndex < 1) DIE("Invalid decrypt argc: %d", argc);
    if (!decrypt && argc-flagIndex < 2) DIE("Invalid encrypt argc: %d", argc);

    char* archiveName = argv[flagIndex];
    int archiveNameLen = strlen(archiveName);

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

    // make room for .far with null terminator
    char* archiveFar = calloc(archiveNameLen + 5, sizeof(char));
    sprintf(archiveFar, "%s.far", archiveName);

    char* archiveLZW = calloc(archiveNameLen + 5, sizeof(char));
    sprintf(archiveLZW, "%s.lzw", archiveName);

    if (decrypt)
    {
        decryptRSA(password, archiveName, archiveLZW);
        decode(archiveLZW, archiveFar);
        extract(archiveFar);
    }
    else
    {
        archive(archiveFar, argc-flagIndex-1, argv+flagIndex+1);
        encode(archiveFar, archiveLZW);
        encryptRSA(password, archiveLZW, archiveName);
    }
    
    if (showPassword) free(password);
    free(archiveFar);
    free(archiveLZW);
}







