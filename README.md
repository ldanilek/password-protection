# password-protection
Archives, compresses, and password-protects a list of files and directories from the command line.

Uses techniques from problem sets across multiple universities:

* Yale's CS323
    * Far for the archiving of multiple files and directories into one file
    * LZW for the compression of that file, and using two names for the same program
    * Bsh for the multiprocessing of the three stages and piping between them
    * CRC (lecture, not problem set) for the verification of each file
* Harvard's CS50
    * Crypto for the salted hashing of passwords
* Dartmouth's CS1
    * Public-key cryptography for the RSA encryption

# To Use

## Initial setup

Clone or download the Github repository.

If your machine runs linux, you may need to replace the ```#define MAC 1``` in encrypt.h with ```#define MAC 0``` which reduces the possible features but allows it to compile.

If you can [install GMP](https://gmplib.org) (```make gmp```) and Openssl (```make openssl```), please do so. If you cannot, skip to the Compression-only section below.

If you only want to install on one computer, simply run ```make install```. Otherwise, follow these instructions:

1. In the command line, run ```make keys```. This will personalize your encryption system by writing random RSA keys to the keys.h file.
2. Run ```make``` - repeat with the same keys.h on all computers for which you want to encrypt or decrypt.
3. Encrypt or remove the file keys.h, and run ```make clean``` - this is critical for security
4. Optional: move encrypt and decrypt to a directory in your $PATH variable (done automatically by ```make link``` or ```make install```)

## Everyday Use

* ```encrypt [options] ArchiveName File1 File2 ...```
* ```decrypt [options] ArchiveName```

See encrypt.h for complete description of flags and restrictions

# Compression-only

This mode does not require GMP or openssl (the only nonstandard libraries used). It archives the listed files and compresses with LZW but does not encrypt or password-protect the file.

## Initial setup

1. Remove -DENCRYPT from line 1 of Makefile, so it reads ```DEFS =```
2. Run ```make compression```

## Everyday use

* ```lzwcompress [options] ArchiveName File1 File2 ...```
* ```lzwdecompress [options] ArchiveName```

See encrypt.h for description of flags and restrictions. In compression-only mode, the -p, -i, and -c flags are not allowed.

# Assumptions

Security of this program is based on the following assumptions:

* Decompiling a C executable to discover #define'd numerical literals (the RSA keys) is hard
* SHA1 hashing is non-invertible
* RSA encryption isn't invertible without the keys

# To Customize

Listed are a few constants you can change to trade security for speed.

* pBits and qBits in keygenerator.py, which will change the length of the RSA keys. Longer keys are more secure and make each step of encryption slower, but the cleartext is divided into chucks of size approximately pBits+qBits, so longer keys means fewer steps of encryption.
* assurance in keygenerator.py, which will change the probablility that p and q are prime (necessary for RSA to be secure)
* SALT_LEN in rsa.c will change the length of the password salt
* MAX_BITS in lzw.c will change the maximum size of the prefix table, which will affect compression factors

# Todo

Still on the list of things to do:

* Use password hash as seed for pseudorandomnumber generator which generates RSA keys on the fly.
* Catch the SIGINT signal so ^C in secure password entry doesn't mess up terminal.
* Salt the encryption so the same message is encrypted to different data
* Archive symbolic links
* Obscure the secret key inside the executable