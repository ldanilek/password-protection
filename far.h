/**
 * Archive multiple files and directories into a single files
 * Extract from a file of the same format back
 *
 * Archiving is done recursively, so be wary of archiving very deep directories
 */

// input file descriptor for writing to archive
// archives each node into the file in encoded format
void archive(int archive, int nodeC, char** nodes);

// input file descriptor for reading from archive
void extract(int archive);
