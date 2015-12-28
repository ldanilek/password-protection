#include "encrypt.h"
#include <libgen.h>

int main(int argc, char** argv)
{
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
    else
    {
        DIE("Invalid program name %s", argv[0]);
    }

    
}