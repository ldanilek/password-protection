# password-protection
Archives, compresses, and password-protects a list of files and directories from the command line.

Uses techniques from problem sets in Yale's CS323 (Far and LZW), Harvard's CS50 (Crypto), and Dartmouth's CS1 (Public-key cryptography)

## Assumptions

Security of this program is based on the following assumptions:

* Decompiling a C executable to discover #define'd numerical literals (the RSA keys) is hard
* SHA1 hashing is non-invertible
* RSA encryption isn't invertible without the keys

# To Use

## Initial setup

If you can [install GMP](https://gmplib.org) and Openssl (I used the command ```brew install openssl; brew link openssl --force```), please do so. If you cannot, skip to the Compression-only section below.

If you only want to install on one computer, simply run ```make install```. Otherwise, follow these instructions:

1. In the command line, run ```python keygenerator.py```. This will personalize your encryption system by writing random RSA keys to the keys.h file.
2. Run ```make``` - repeat with the same keys.h on all computers for which you want to encrypt or decrypt.
3. Encrypt or remove the file keys.h - this is critical for security
4. Optional: move encrypt and decrypt to a directory in your $PATH variable

## Everyday Use

* ```encrypt flags ArchiveName File1 File2 ...```
* ```decrypt flags ArchiveName```

See encrypt.h for complete description of flags and restrictions

# Compression-only

This mode does not require GMP or openssl (the only nonstandard libraries used). It archives the listed files and compresses with LZW but does not encrypt or password-protect the file.

## Initial setup

1. Remove -DENCRYPT from line 1 of Makefile, so it reads ```DEFS =```
2. Run ```make compression```
3. Optional: move the executables compress and decompress to a directory in your $PATH variable

## Everyday use

* ```compress flags ArchiveName File1 File2 ...```
* ```decompress flags ArchiveName```

See encrypt.h for description of flags and restrictions. In compression-only mode, the -p flag is not allowed.

# To Customize

Listed are a few constants you can change to trade security for speed.

* pBits and qBits in keygenerator.py, which will change the length of the RSA keys
* assurance in keygenerator.py, which will change the probablility that p and q are prime (necessary for RSA to be secure)
* SALT_LEN in rsa.c will change the length of the password salt
* MESSAGE_PROGRESS_GROUPS in rsa.c will change the number of asterisks printed while encrypting/decrypting
* MAX_BITS in lzw.c will change the maximum size of the prefix table, which will affect compression factors


