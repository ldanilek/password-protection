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
#include "crc.h"

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
    // store these so they can be restored
    struct timeval times[2];
    // default value so encrypt on linux (no flags) can be decrypted on mac
    u_long flags = 0;
#if MAC
    // pretty sure this one doesn't work
    TIMESPEC_TO_TIMEVAL(times, &nodeData.st_atimespec);
    TIMESPEC_TO_TIMEVAL(times+1, &nodeData.st_mtimespec);
    flags = nodeData.st_flags;
#else
    times[0].tv_sec = nodeData.st_atime;
    times[1].tv_sec = nodeData.st_mtime;
    times[0].tv_usec = times[1].tv_usec = 0;
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

    // write the times and flags of this node
    int timeSize = sizeof(struct timeval) * 2;
    if (write(archive, times, timeSize)<timeSize) SYS_DIE("write");
    // write the flags
    if (write(archive, &flags, sizeof(flags))<sizeof(flags)) SYS_DIE("write");

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
            int nameLen = strlen(subnode->d_name);
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
        FILE* file = fopen(node, "r");
        if (!file) SYS_ERR_DONE("fopen");

        int encoded = open(nodeLZW, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (encoded < 0) SYS_ERR_DONE("open lzw");

        // compute CRC and pipe file to encode
        int computeCRCToEncodePipe[2];
        if (pipe(computeCRCToEncodePipe)) SYS_DIE("pipe");

        bool didEncode = true;

        pid_t encodeProcess = fork();
        if (encodeProcess < 0) SYS_DIE("fork");
        if (encodeProcess == 0)
        {
            if (close(computeCRCToEncodePipe[1])) SYS_DIE("close");
            // encode this file
            PROGRESS("Encoding %s to %s", node, nodeLZW);
            didEncode = encode(computeCRCToEncodePipe[0], encoded);
            PROGRESS("Encoding %s complete", node);

            exit(didEncode ? 0 : UNCOMPRESSABLE);
        }

        if (close(computeCRCToEncodePipe[0])) SYS_ERROR("close");

        unsigned int checksum = computeCRC(file, computeCRCToEncodePipe[1]);
        if (fclose(file)) SYS_ERROR("fclose");
        if (close(computeCRCToEncodePipe[1])) SYS_DIE("close");

        if (write(archive, &checksum, sizeof(checksum)) < sizeof(checksum))
            SYS_DIE("write");

        int encodeStatus = 0;
        if (waitpid(encodeProcess, &encodeStatus, 0) < 0) SYS_DIE("waitpid");

        if (STAT(encodeStatus) == UNCOMPRESSABLE) didEncode = false;
        else if (encodeStatus) DIE("Encode status %d", STAT(encodeStatus));

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
            if (!f) SYS_DIE("fopen");
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
        struct timeval times[2];
        int timeSize = sizeof(struct timeval) * 2;
        if (!rdhang(archive, times, timeSize))
            SYS_DIE("Unable to read timevals");
        u_long flags;
        if (!rdhang(archive, &flags, sizeof(flags)))
            SYS_DIE("Unable to read flags");
        // extract all prefix directories
        bool errorExtractingParents = false;
        for (int i=1; i < nodeNameLen; i++)
        {
            if (nodeName[i] == '/')
            {
                nodeName[i] = '\0';
                mkdir(nodeName, mode);
                if (errno != EEXIST && errno != 0)
                {
                    if(!quiet) fprintf(stderr, "mkdir(%s)\n", nodeName);
                    SYS_ERROR("mkdir");
                    errorExtractingParents = true;
                    break;
                }
                nodeName[i] = '/';
            }
        }
        if (errorExtractingParents) continue;
        // done extracting prefix directories. now nodeName should be available
        if (nodeName[nodeNameLen-1] != '/')
        {
            // directories should be already taken care of
            // this is a regular file
            off_t size;
            if (!rdhang(archive, &size, sizeof(size)))
                DIE("%s", "Unable to read size");

            unsigned int checksum;
            if (!rdhang(archive, &checksum, sizeof(checksum)))
                DIE("%s", "Unable to read checksum");

            FILE* file = fopen(nodeName, "w");
            if (!file) SYS_ERROR("fopen"); // permissions error

            // decode in another process, piping results to CRC check
            int decodeToCheckPipe[2];
            if (pipe(decodeToCheckPipe)) SYS_DIE("pipe");

            pid_t decodeProcess = fork();
            if (decodeProcess < 0) SYS_DIE("fork");
            if (decodeProcess == 0)
            {
                if (close(decodeToCheckPipe[0])) SYS_DIE("close");
                // decode into the pipe
                decode(archive, decodeToCheckPipe[1], size);
                exit(0); // sends EOF, so check until EOF
            }
            
            if (close(decodeToCheckPipe[1])) SYS_DIE("close");
            bool check = checkCRC(decodeToCheckPipe[0], file, checksum);
            if (!check) DIE("%s", "Cyclic Redundancy Check failed");

            if (close(decodeToCheckPipe[0])) SYS_ERROR("close");
            // process is already dead, because checkCRC() finished; reap zombie
            int status = 0;
            if (waitpid(decodeProcess, &status, 0) < 0)
            if (status) DIE("Status of decodeProcess is %d", status);

            if (file && fclose(file)) SYS_ERROR("fclose");
            // check setattrlist(2)
        }
        if (chmod(nodeName, mode)) SYS_ERROR("chmod");
#if MAC
        if (chflags(nodeName, flags)) SYS_ERROR("chflags");
#endif
        if (utimes(nodeName, times)) SYS_ERROR("utimes");

        PROGRESS("Finished extraction of node %s", nodeName);
    }

    STATUS("%s", "Extraction complete");
}
