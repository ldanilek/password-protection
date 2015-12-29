DEFS = -DENCRYPT

# compiler to use
CC = clang

# flags to pass compiler
CFLAGS = -ggdb3 -O0 -Qunused-arguments -std=c11 -Wall -Werror $(DEFS)

# name for executable
EXE = encrypt

# space-separated list of libraries, if any,
# each of which should be prefixed with -l
LIBS = -lgmp -lssl -lcrypto

C_SRCS = encrypt.c far.c bitcode.c stringtable.c stringarray.c lzw.c

C_HDRS = encrypt.h far.h stringarray.h stringtable.h lzw.h bitcode.h

# space-separated list of header files
HDRS = $(C_HDRS) keys.h rsa.h

# space-separated list of source files
SRCS = $(C_SRCS) rsa.c

# automatically generated list of object files
OBJS = $(SRCS:.c=.o)

C_OBJS = $(C_SRCS:.c=.o)

all: encrypt decrypt

# main target
$(EXE): $(OBJS) $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

compression: compress decompress

compress: $(C_OBJS) $(C_HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $(C_OBJS)

decompress: compress
	ln -f compress decompress

decrypt: $(EXE)
	ln -f $(EXE) decrypt

keys:
	python keygenerator.py

link: encrypt decrypt
	cp encrypt /usr/local/bin/encrypt
	cp decrypt /usr/local/bin/decrypt

install: keys link
	rm -f keys.h

# dependencies 
$(OBJS): $(HDRS) Makefile

# housekeeping
clean:
	rm -f core $(EXE) *.o decrypt compress decompress
