# compiler to use
CC = clang

# flags to pass compiler
CFLAGS = -ggdb3 -O0 -Qunused-arguments -std=c11 -Wall -Werror

# name for executable
EXE = encrypt

# space-separated list of header files
HDRS = encrypt.h far.h stringarray.h stringtable.h lzw.h bitcode.h keys.h rsa.h

# space-separated list of libraries, if any,
# each of which should be prefixed with -l
LIBS = -lgmp

# space-separated list of source files
SRCS = encrypt.c far.c bitcode.c stringtable.c stringarray.c lzw.c rsa.c

# automatically generated list of object files
OBJS = $(SRCS:.c=.o)

all: encrypt decrypt

# main target
$(EXE): $(OBJS) $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

decrypt: $(EXE)
	ln -f $(EXE) decrypt

# dependencies 
$(OBJS): $(HDRS) Makefile

# housekeeping
clean:
	rm -f core $(EXE) *.o decrypt
