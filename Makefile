CFLAGS := -Wall -Werror -g
CC := gcc
LIBDIR := /home/parsons/Dev/lib
LIBFLAGS := -fpic -shared

all: fdwrite tracer

#libprocinfo: libprocinfo.c
#	$(CC) -o $(LIBDIR)/$@.so $^ $(CFLAGS) $(LIBFLAGS)

fdwrite: fd_write.c tracer.o
	$(CC) -o $@ $(CFLAGS) $^ 

tracer: tracer.c
	$(CC) -o $@.o $(CFLAGS) $^