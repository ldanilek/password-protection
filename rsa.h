/**
 * First hashes the password to the beginning of the file.
 * Then performs RSA encryption using keys from keys.h
 */

#ifndef RSA
#define RSA

// removes inputName file, overwrites outputName file
void encryptRSA(char* password, char* inputName, char* outputName);

// removes inputName file, overwrites outputName file
void decryptRSA(char* password, char* inputName, char* outputName);

#endif