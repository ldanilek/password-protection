/**
 * Archive multiple files and directories into a single files
 * Extract from a file of the same format back
 *
 * Archiving is done recursively, so be wary of archiving very deep directories
 */

void archive(char* archiveName, int nodeC, char** nodes);

void extract(char* archiveName);