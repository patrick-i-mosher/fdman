#ifndef CALL_X86_H
#define CALL_X86_H

// Resolve conflicts between sys/ptrace.h and linux/ptrace.h
#ifdef _LINUX_PTRACE_H
# undef PTRACE_TRACEME
# undef PTRACE_PEEKTEXT
# undef PTRACE_PEEKDATA
# undef PTRACE_POKETEXT
# undef PTRACE_POKEDATA
# undef PTRACE_CONT
# undef PTRACE_KILL
# undef PTRACE_SINGLESTEP
# undef PTRACE_ATTACH
# undef PTRACE_DETACH
# undef PTRACE_SYSCALL
# undef PTRACE_SETOPTIONS
# undef PTRACE_GETEVENTMSG      
# undef PTRACE_GETSIGINFO       
# undef PTRACE_SETSIGINFO
# undef PTRACE_GETREGSET        
# undef PTRACE_SETREGSET        
# undef PTRACE_SEIZE            
# undef PTRACE_INTERRUPT        
# undef PTRACE_LISTEN           
# undef PTRACE_PEEKSIGINFO
# undef PTRACE_PEEKSIGINFO_SHARED
# undef PTRACE_GETSIGMASK       
# undef PTRACE_SETSIGMASK     
# undef PTRACE_SECCOMP_GET_FILTER           
# undef PTRACE_EVENT_FORK
# undef PTRACE_EVENT_VFORK
# undef PTRACE_EVENT_CLONE
# undef PTRACE_EVENT_EXEC
# undef PTRACE_EVENT_VFORK_DONE
# undef PTRACE_EVENT_EXIT
# undef PTRACE_GETREGS
# undef PTRACE_SETREGS
# undef PTRACE_GETFPREGS
# undef PTRACE_SETFPREGS
# undef PTRACE_GETFPXREGS
# undef PTRACE_SETFPXREGS
# undef PTRACE_O_TRACESYSGOOD
# undef PTRACE_O_TRACEFORK
# undef PTRACE_O_TRACEVFORK
# undef PTRACE_O_TRACECLONE
# undef PTRACE_O_TRACEEXEC
# undef PTRACE_O_TRACEVFORKDONE
# undef PTRACE_O_TRACEEXIT
# undef PTRACE_O_TRACESECCOMP
# undef PTRACE_O_MASK
#endif

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
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// number of bytes in a JMP/CALL rel32 instruction
#define REL32_SZ 5
#define LIB_C_STR "/libc-2"

typedef struct call_x86_context {
    pid_t pid;
    char * lib_str;
    void * local_libc_addr;
    void * remote_libc_addr;
    char * format;
    struct user_regs_struct * register_save_state;
    struct user_regs_struct * newregs;
    uint8_t old_word[8];
    uint8_t new_word[8];
} call_x86_context;

void *find_library(pid_t pid, const char *libname);
int poke_text(pid_t pid, void *where, void *new_text, void *old_text,
              size_t len);
void putdata(pid_t child, long addr, char *str, int len);
int do_wait(const char *name);
int singlestep(pid_t pid);
void check_yama(void);
int32_t compute_jmp(void *from, void *to);
int attach_process(pid_t pid);
int save_register_state(pid_t pid, struct user_regs_struct * register_save_state);
void syscall_munmap(call_x86_context * call_ctx, void * addr);
void * syscall_mmap(call_x86_context * call_ctx);
call_x86_context * init_call_context(pid_t pid);
int insert_call_instruction(call_x86_context * call_ctx, void * mmap_memory, void * remote_func_addr);
int set_call_registers(call_x86_context * call_ctx, va_list vl, int nargs);
void release_resources(call_x86_context * call_ctx, void * mmap_memory);
long call(call_x86_context * call_ctx, void *local_function, int nargs, ...);
#endif