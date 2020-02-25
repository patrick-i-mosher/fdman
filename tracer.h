#ifndef TRACER_H
#define TRACER_H

#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define ARM_cpsr uregs[16]
#define ARM_pc uregs[15]
#define ARM_lr uregs[14]
#define ARM_sp uregs[13]
#define ARM_ip uregs[12]
#define ARM_fp uregs[11]
#define ARM_r10 uregs[10]
#define ARM_r9 uregs[9]
#define ARM_r8 uregs[8]
#define ARM_r7 uregs[7]
#define ARM_r6 uregs[6]
#define ARM_r5 uregs[5]
#define ARM_r4 uregs[4]
#define ARM_r3 uregs[3]
#define ARM_r2 uregs[2]
#define ARM_r1 uregs[1]
#define ARM_r0 uregs[0]
#define ARM_ORIG_r0 uregs[17]
#define ARM_VFPREGS_SIZE (32 * 8 + 4)
#define CPSR_T_MASK ( 1u << 5 )

pid_t _pid;
void *_dlopen;
void *_dlsym;
//void *_dlerror;
void *_calloc;
void *_free;
void *_dup2;
void *_pipe;

struct pt_regs {
    long uregs[18];
};

void *findFunction( const char* library, void* local_addr );
long findLibrary( const char *library, pid_t pid); 
long trace( int request, void *addr, size_t data);

unsigned long myDlopen( const char *libname ); 
unsigned long myDlsym( unsigned long dl, const char *symname );

unsigned long myDup2(int oldfd, int newfd);
void myPipe(int pipefd[2]);
void myFree( unsigned long p ); 
void end_trace();
void start_trace(pid_t pid); 
unsigned long copyString( const char *s );
unsigned long call( void *function, int nargs, ... );

#endif
