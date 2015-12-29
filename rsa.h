/**
 * First hashes the password to the beginning of the file.
 * Then performs RSA encryption using keys from keys.h
 */

#ifndef RSA
#define RSA

void encryptRSA(char* password, char* inputName, char* outputName);

void decryptRSA(char* password, char* inputName, char* outputName);

#endif