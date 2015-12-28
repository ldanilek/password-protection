#include "far.h"
#include "encrypt.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/**
 * Given archive open for writing and path to inode, copy node into archive
 */
void archiveNode(FILE* archive, char* node)
{
    int nodeLen = strlen(node);
    while (nodeLen > 0 && node[nodeLen-1] == '/') node[--nodeLen] = '\0';
    PROGRESS("Archiving node %s", node);
    struct stat nodeData;
    if (lstat(node, &nodeData)) SYS_ERR_DONE("lstat");
    mode_t mode = nodeData.st_mode;
    if (S_ISDIR(mode))
    {
        // append a / to make sure it's extracted as a directory
        node[nodeLen++] = '/';
    }
    else if (!S_ISREG(mode))
    {
        STATUS("Unrecognized inode type %d", nodeData.st_mode);
        return;
    }
    // write the name of this node
    if (fwrite(&nodeLen, sizeof(nodeLen), 1, archive)<1) SYS_DIE("fwrite");
    if (fwrite(node, sizeof(char), nodeLen, archive)<nodeLen) SYS_DIE("fwrite");
    // write the mode of this node
    if (fwrite(&mode, sizeof(mode), 1, archive)<1) SYS_DIE("fwrite");
    if (S_ISDIR(mode))
    {
        node[--nodeLen] = '\0';
        
        // in the case of an unopenable directory, report error after archiving
        DIR* directory = opendir(node);
        if (!directory) SYS_ERR_DONE("opendir");
        // now look through each thing in directory
        struct dirent* subnode;
        while ((subnode = readdir(directory)))
        {
            if (!strcmp(subnode->d_name, ".") || !strcmp(subnode->d_name, ".."))
                continue;
            char* subNodePath = calloc(nodeLen + subnode->d_namlen + 2, 1);
            sprintf(subNodePath, "%s/%s", node, subnode->d_name);
            archiveNode(archive, subNodePath);
            free(subNodePath);
        }

        if (closedir(directory)) SYS_ERR_DONE("closedir");
    }
    else
    {
        // first put length (so know where to stop when reading)
        off_t size = nodeData.st_size;
        if (fwrite(&size, sizeof(size), 1, archive)<1) SYS_DIE("fwrite");
        // regular file
        FILE* file = fopen(node, "r");
        if (!file) SYS_ERR_DONE("fopen");
        int c;
        while ((c = fgetc(file)) != EOF)
        {
            fputc(c, archive);
        }
        if (fclose(file)) SYS_ERR_DONE("fclose");
    }
}

void archive(char* archiveName, int nodeC, char** nodes)
{
    STATUS("Beginning archive to %s", archiveName);

    FILE* archive = fopen(archiveName, "w");
    if (!archive) DIE("Can't write to archive at %s", archiveName);

    fputc(0, archive);

    for (int i = 0; i < nodeC; i++)
    {
        archiveNode(archive, nodes[i]);
    }

    if (fclose(archive)) SYS_ERROR("fclose");
    STATUS("Archive to %s complete", archiveName);
}

void extract(char* archiveName)
{
    STATUS("Begin extraction from %s", archiveName);

    FILE* archive = fopen(archiveName, "r");
    if (!archive) DIE("Can't read from archive at %s", archiveName);

    int prefixByte = fgetc(archive);
    if (prefixByte != 0) DIE("Prefix byte nonzero: %d", prefixByte);

    int nodeNameLen;
    while (fread(&nodeNameLen, sizeof(nodeNameLen), 1, archive) == 1)
    {
        char nodeName[nodeNameLen + 1];
        if (fread(nodeName, sizeof(char), nodeNameLen, archive) < nodeNameLen)
            DIE("Unable to read name of length %d", nodeNameLen);
        nodeName[nodeNameLen] = '\0';
        PROGRESS("Extracting node %s", nodeName);
        mode_t mode;
        if (fread(&mode, sizeof(mode), 1, archive) < 1)
            DIE("%s", "Unable to read mode");
        // extract all prefix directories
        bool errorExtractingParents = false;
        for (int i=0; i < nodeNameLen; i++)
        {
            if (nodeName[i] == '/')
            {
                nodeName[i] = '\0';
                mkdir(nodeName, mode);
                if (errno != EEXIST && errno != 0)
                {
                    SYS_ERROR("mkdir");
                    errorExtractingParents = true;
                    break;
                }
                nodeName[i] = '/';
            }
        }
        if (errorExtractingParents) continue;
        if (nodeName[nodeNameLen-1] != '/')
        {
            // directories should be already taken care of
            // this is a regular file
            off_t size;
            if (fread(&size, sizeof(size), 1, archive) < 1)
                DIE("%s", "Unable to read size");
            FILE* file = fopen(nodeName, "w");
            for (off_t i=0; i<size; i++)
            {
                int c = fgetc(archive);
                if (c == EOF) DIE("%s", "File ended unexpectedly");
                fputc(c, file);
            }
            if (fclose(file)) SYS_ERROR("fclose");
        }
    }

    STATUS("Extraction from %s complete", archiveName);
}
