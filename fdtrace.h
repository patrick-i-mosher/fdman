#ifndef FDTRACE_H
#define FDTRACE_H

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/limits.h>
#include <linux/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include "call_x86.h"

/**
 * DATA STRUCTURES
**/

typedef struct file_context {
	char * target_file;	
	DIR * dir;				
	struct dirent * entry;
	struct stat * stat_buf;
	char * proc_path;
} file_context;

typedef struct read_context {
	
} read_context;

typedef struct write_syscall_args {
	unsigned int sys_write_fd;
	long sys_write_buf_addr;
	size_t sys_write_count;
} write_syscall_args;

typedef struct write_context {
	char * data_to_write;
	long write_replacement_buf_addr;
	write_syscall_args sys_write_args;
} write_context;

typedef struct general_context {
	read_context * read_ctx;
	write_context * write_ctx;
	file_context * file_ctx;
	call_x86_context * call_ctx;
	long pid;
	struct user_regs_struct * regs;
	void * calloc_ptr;
	int target_fd;
	int fatal_error;
	int log_file;
} general_context;

/**
 * GLOBAL VARIABLES
**/

general_context * gen_ctx;

/**
 * FUNCTION DECLARATIONS 
 **/

void init(int argc, char** argv);
void terminate();
void scan_fd();
void intercept_write();
void write_log(char * log_level, char * err_file, int line_number, char * log_str);
#endif