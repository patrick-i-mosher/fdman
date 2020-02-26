#ifndef CALL_X86_H
#define CALL_X86_H

#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// number of bytes in a JMP/CALL rel32 instruction
#define REL32_SZ 5
#define LIB_C_STR "/libc-2"

void *find_library(pid_t pid, const char *libname);
void check_yama(void);
int32_t compute_jmp(void *from, void *to);
int do_wait(const char *name);
long call(pid_t pid, char *lib_string, void *local_function, int nargs, ...);
int poke_text(pid_t pid, void *where, void *new_text, void *old_text,
              size_t len);
int singlestep(pid_t pid);
void putdata(pid_t child, long addr, char *str, int len);




#endif