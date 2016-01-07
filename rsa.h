/**
 * First hashes the password to the beginning of the file.
 * Then performs RSA encryption using keys from keys.h
 */

#ifndef RSA
#define RSA

// password will be zeroed ASAP. password NULL is DEFAULT_PASSWORD (not zeroed)

// reads from file descriptor inFile, writes to file descriptor outFile
// breaks file into chunks of about 2kb
void encryptRSA(char* password, int inFile, int outFile);

// removes inputName file, overwrites outputName file
void decryptRSA(char* password, int inFile, int outFile);

#endif