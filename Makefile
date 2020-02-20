CFLAGS := -Wall -Werror -g
CC := gcc
LIBDIR := /home/parsons/Dev/lib
LIBFLAGS := -fpic -shared

all: clean libprocinfo fdwrite

libprocinfo: libprocinfo.c
	$(CC) -o $(LIBDIR)/$@.so $^ $(CFLAGS) $(LIBFLAGS)

fdwrite: fd_write.c
	$(CC) -o $@ $(CFLAGS) $^ -L$(LIBDIR) -l:libprocinfo.so

clean:
	rm $(LIBDIR)/libprocinfo.so