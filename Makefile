DEFS = -DENCRYPT

# compiler to use
CC = gcc

# for clang
# -Qunused-arguments -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include

# flags to pass compiler
CFLAGS = -ggdb3 -std=c99 -Wall -Werror -I/usr/local/include $(DEFS)

# name for executable
EXE = encrypt

# space-separated list of libraries, if any,
# each of which should be prefixed with -l
LIBS = -lgmp -lssl -lcrypto

C_SRCS = encrypt.c far.c bitcode.c stringtable.c stringarray.c lzw.c crc.c

C_HDRS = encrypt.h far.h stringarray.h stringtable.h lzw.h bitcode.h crc.h

# space-separated list of header files
HDRS = $(C_HDRS) rsa.h

# space-separated list of source files
SRCS = $(C_SRCS) rsa.c

# automatically generated list of object files
OBJS = $(SRCS:.c=.o)

C_OBJS = $(C_SRCS:.c=.o)

all: encrypt decrypt

# main target
$(EXE): $(OBJS) $(HDRS) Makefile
	$(CC) $(CFLAGS) -L/usr/local/lib -o $@ $(OBJS) $(LIBS)

compression: lzwcompress lzwdecompress
	cp lzwcompress /usr/local/bin/lzwcompress
	cp lzwdecompress /usr/local/bin/lzwdecompress

lzwcompress: $(C_OBJS) $(C_HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $(C_OBJS)

lzwdecompress: lzwcompress
	ln -f lzwcompress lzwdecompress

decrypt: $(EXE)
	ln -f $(EXE) decrypt

keys:
	python keygenerator.py

link: encrypt decrypt
	cp encrypt /usr/local/bin/encrypt
	cp decrypt /usr/local/bin/decrypt

gmp:
	brew install gmp
	brew link gmp --force

openssl:
	brew install openssl
	brew link openssl --force

install: keys link
	rm -f keys.h

# dependencies 
$(OBJS): $(HDRS) Makefile

# housekeeping
clean:
	rm -f core $(EXE) *.o decrypt lzwcompress lzwdecompress
