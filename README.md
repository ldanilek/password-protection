# password-protection
Archives, compresses, and password-protects a list of files and directories from the command line.

Uses techniques from problem sets in Yale's CS323 (Far and LZW), Harvard's CS50 (Crypto), and Dartmouth's CS1 (Public-key cryptography)

# Warning label: still in development. Do not use until finalized

## Assumptions

Security of this program is based on the following assumptions:

* Decompiling a C executable to discover numerical literals (RSA keys) is hard
* DES hashing is non-invertible
* RSA encryption isn't invertible without the keys

# To Use

## Initial setup

* Install (GMP)[https://gmplib.org]
* In the command line, run ```python keygenerator.py```. This will personalize your encryption system by writing random RSA keys to the keys.h file.
* Run ```make``` - repeat with the same keys.h on all computers for which you want to encrypt or decrypt.
* Encrypt or remove the file keys.h - this is critical for security
* Optional: move encrypt and decrypt to a directory in your $PATH variable

## Everyday Use

* ```encrypt flags ArchiveName File1 File2 ...```
* ```decrypt flags ArchiveName```

See encrypt.h for complete description of flags and restrictions