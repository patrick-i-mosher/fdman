CFLAGS := -Wall -Werror -g -fPIC
CC := gcc
LIBDIR := /home/parsons/Dev/lib
LIBFLAGS :=  -shared

all: fdwrite fdtrace

fdwrite: fd_write.c
	$(CC) -o $@ $(CFLAGS) $^ 

fdtrace: fdtrace_main.c fdtools.o steque.o call_x86.o
	$(CC) -o $@ $(CFLAGS) $^

%.o : %.c
	$(CC) -c -o $@ $(CFLAGS) $<

.PHONY: clean

clean:
	rm *.o