#define _GNU_SOURCE
#include "far.h"
#include "encrypt.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include "bitcode.h"
#include "lzw.h"

/**
 * Given archive open for writing and path to inode, copy node into archive
 * Input file descriptor open for writing
 */
void archiveNode(int archive, char* node, char* nodeLZW)
{
    int nodeLen = strlen(node);
    while (nodeLen > 0 && node[nodeLen-1] == '/') node[--nodeLen] = '\0';
    PROGRESS("Archiving node %s", node);
    struct stat nodeData;
    if (lstat(node, &nodeData)) SYS_ERR_DONE("lstat");

    mode_t mode = nodeData.st_mode;
#if MAC
    // store these so they can be restored
    struct timeval times[2];
    // pretty sure this one doesn't work
    TIMESPEC_TO_TIMEVAL(times, &nodeData.st_atimespec);
    TIMESPEC_TO_TIMEVAL(times+1, &nodeData.st_mtimespec);
    u_long flags = nodeData.st_flags;
#endif

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
    if (write(archive, &nodeLen, sizeof(nodeLen))<sizeof(nodeLen))
        SYS_DIE("write");
    if (write(archive, node, nodeLen)<nodeLen) SYS_DIE("write");
    // write the mode of this node
    if (write(archive, &mode, sizeof(mode))<sizeof(mode)) SYS_DIE("write");
#if MAC
    // write the times and flags of this node
    int timeSize = sizeof(struct timeval) * 2;
    if (write(archive, times, timeSize)<timeSize) SYS_DIE("write");
    // write the flags
    if (write(archive, &flags, sizeof(flags))<sizeof(flags)) SYS_DIE("write");
#endif

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
#if MAC
            int nameLen = subnode->d_namlen;
#else
            int nameLen = strlen(subnode->d_name);
#endif
            if (nameLen >= 4 && strcmp(subnode->d_name+nameLen-4, ".lzw")==0)
                continue;
            char* subNodePath = calloc(nodeLen + nameLen + 2, 1);
            sprintf(subNodePath, "%s/%s", node, subnode->d_name);
            archiveNode(archive, subNodePath, nodeLZW);
            free(subNodePath);
        }

        if (closedir(directory)) SYS_ERR_DONE("closedir");
        if (removeOriginal && rmdir(node)) SYS_ERR_DONE("rmdir");
    }
    else
    {
        // first put length (so know where to stop when reading)
        off_t size = nodeData.st_size;
        if (write(archive, &size, sizeof(size))<sizeof(size)) SYS_DIE("write");
        // regular file
        int file = open(node, O_RDONLY);
        if (file < 0) SYS_ERR_DONE("open");

        int encoded = open(nodeLZW, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (encoded < 0) SYS_ERR_DONE("open lzw");

        // encode this file
        PROGRESS("Encoding %s to %s", node, nodeLZW);
        bool didEncode = encode(file, encoded);
        PROGRESS("Encoding %s complete", node);
        if (close(encoded)) SYS_ERROR("close");
        if (close(file)) SYS_ERROR("close");

        if (didEncode)
        {
            // write from nodeLZW to archive
            FILE* lzw = fopen(nodeLZW, "r");
            if (!lzw) SYS_DIE("fopen");
            int c;
            while ((c = fgetc(lzw)) != EOF)
            {
                fdputc(c, archive);
            }
            if (fclose(lzw)) SYS_ERROR("close");
        }
        else
        {
            fdputc(0, archive);
            // copy from node to archive
            FILE* f = fopen(node, "r");
            if (!f) SYS_DIE("open");
            int c;
            while ((c = fgetc(f)) != EOF)
            {
                fdputc(c, archive);
            }
            if (fclose(f)) SYS_ERROR("close");
        }
        if (remove(nodeLZW)) SYS_ERROR("remove");
        
        if (removeOriginal && remove(node)) SYS_ERROR("remove");
    }
}

/**
 * Input archive file descriptor open for writing.
 */
void archive(int archive, char* nodeLZW, int nodeC, char** nodes)
{
    STATUS("%s", "Archiving");

    for (int i = 0; i < nodeC; i++) archiveNode(archive, nodes[i], nodeLZW);

    PROGRESS("%s", "Archive complete");
}

void extract(int archive)
{
    STATUS("%s", "Extracting");

    int nodeNameLen;
    int lenSize = sizeof(nodeNameLen);
    while (rdhang(archive, &nodeNameLen, lenSize))
    {
        char nodeName[nodeNameLen + 1];
        if (!rdhang(archive, nodeName, nodeNameLen))
            SYS_DIE("Unable to read name");
        nodeName[nodeNameLen] = '\0';
        PROGRESS("Extracting node %s", nodeName);
        mode_t mode;
        if (!rdhang(archive, &mode, sizeof(mode)))
            SYS_DIE("Unable to read mode");
#if MAC
        struct timeval times[2];
        int timeSize = sizeof(struct timeval) * 2;
        if (!rdhang(archive, times, timeSize))
            SYS_DIE("Unable to read timevals");
        u_long flags;
        if (!rdhang(archive, &flags, sizeof(flags)))
            SYS_DIE("Unable to read flags");
#endif
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
            if (!rdhang(archive, &size, sizeof(size)))
                DIE("%s", "Unable to read size");
            FILE* file = fopen(nodeName, "w");
            if (!file) SYS_ERROR("fopen"); // permissions error

            // decode into the file
            decode(archive, fileno(file), size);

            if (file)
            {
                if (fclose(file)) SYS_ERROR("fclose");
                if (chmod(nodeName, mode)) SYS_ERROR("chmod");
#if MAC
                if (chflags(nodeName, flags)) SYS_ERROR("chflags");
                if (utimes(nodeName, times)) SYS_ERROR("utimes");
#endif
            }
            // check setattrlist(2)
        }
        PROGRESS("Finished extraction of node %s", nodeName);
    }

    STATUS("%s", "Extraction complete");
}
