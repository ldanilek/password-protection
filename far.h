/**
 * Archive multiple files and directories into a single files
 * Extract from a file of the same format back
 *
 * Archiving is done recursively, so be wary of archiving very deep directories
 */

// input file descriptor for writing to archive
// archives each node into the file in encoded format
// temporary storage of encoded file goes in nodeLZW
// which must be openable for writing
void archive(int archive, char* nodeLZW, int nodeC, char** nodes);

// input file descriptor for reading from archive
void extract(int archive);
