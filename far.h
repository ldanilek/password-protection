/**
 * Archive multiple files and directories into a single files
 * Extract from a file of the same format back
 *
 * Archiving is done recursively, so be wary of archiving very deep directories
 */

// creates or overwrites file at archiveName
void archive(char* archiveName, int nodeC, char** nodes);

// removes file at archiveName
void extract(char* archiveName);
