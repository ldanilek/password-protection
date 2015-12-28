# password-protection
Archives, compresses, and password-protects a list of files and directories from the command line.

Uses techniques from problem sets in Yale's CS323 (Far and LZW), Harvard's CS50 (Crypto), and Dartmouth's CS1 (Public-key cryptography)

# Still in development. Do not use until finalized

# To Use

## Initial setup

* In the command line, run ```python keygenerator.py```
* Copy the output into the constants at the top of encrypt.c. This will personalize your encryption system
* Run ```make```
* Run ```make``` on all computers for which you want to encrypt or decrypt.
* Encrypt or remove the file encrypt.c
* Optional: move encrypt and decrypt to a directory in your $PATH variable

## Everyday Use

* ```encrypt flags ArchiveName File1 File2 ...```
* ```decrypt flags ArchiveName```

See encrypt.h for complete description of flags and restrictions