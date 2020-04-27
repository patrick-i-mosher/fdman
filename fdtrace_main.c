#include <getopt.h>
#include <stdio.h>
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <fcntl.h>
#include <poll.h>
#include "steque.h"
#include "call_x86.h"
#include "fdtools.h"
/**
 * Usage: fdswap <PID> <Underlying Target>
 * Example: fdswap 23445 /dev/null 
 */

#define DATA_MAX_LEN 1024

#define USAGE																  \
"usage:\n"                                                                    \
"  fdtrace [options]\n"                                                       \
"options:\n"                                                                  \
"  -h                  Show this help message.\n"                             \
"  -p [process_id]     Target process ID\n"                                   

static struct option gLongOptions[] = {
{"pid",           required_argument,      NULL,           'p'},
{"help",          no_argument,            NULL,           'h'},
{NULL,            0,                      NULL,             0}
};

int main(int argc, char** argv) {
	long pid = -1;
	int c;
	opterr = 0;
	while ((c = getopt_long(argc, argv, "hp:", gLongOptions, NULL)) != -1) {
		switch (c) {
		case 'h':
			printf("Usage: %s -p <pid>\n", argv[0]);
			return 0;
			break;
		case 'p':
			pid = strtol(optarg, NULL, 10);
			if ((errno == ERANGE && (pid == LONG_MAX || pid == LONG_MIN)) ||
				(errno != 0 && pid == 0)) {
				perror("strtol");
				return 1;
			}
			if (pid < 0) {
				fprintf(stderr, "cannot accept negative pids\n");
				return 1;
			}
			break;
		case '?':
			if (optopt == 'p') {
				fprintf(stderr, "Option -p requires an argument.\n");
			} else if (isprint(optopt)) {
				fprintf(stderr, "Unknown option `-%c`.\n", optopt);
			} else {
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			}
			return 1;
			break;
			default:
			abort();
		}
	}
	if (pid == -1) {
		fprintf(stderr, "must specify a remote process with -p\n");
		return 1;
	}

	steque_t queue;
	steque_t target_file_q;		
	char * target_file = "/home/parsons/tmp/fdtest"; // my test terminal
	
	DIR * dir = NULL;			
	void * calloc_ptr = (void *)&calloc;
	steque_init(&queue);
	steque_init(&target_file_q);
	// enumerate target process' open file descriptors
	char proc_path[PATH_MAX];
	snprintf(proc_path, PATH_MAX, "/proc/%ld/fd", pid);
	dir = opendir(proc_path);
	if(!dir) {
		perror("Unable to open target directory");
		return 1;
	}
	// Call open() in remote process to get handles to our named pipes	
	
	// Check open file descriptors again to verify pipe creation
	dir = opendir(proc_path);
	if(!dir) {
		perror("Unable to open target directory");
		return 1;
	}
	scan_fd(dir, &queue, pid, target_file);	
	printf("Found %d open file descriptors\n",steque_size(&queue));
	int target_fd;
	while(!steque_isempty(&queue)) {
		int * temp = NULL;
		temp = steque_pop(&queue);				
		target_fd = *temp;
		free(temp);		
	}
	closedir(dir);
	
	// allocate and fill remote buffer for the data we actually want the target processs to write
	// We have to do this now, because we can't do it once the process is stopped later.
	
	//int target_fd = open(target_file, O_RDWR);	
	//struct pollfd pfd[1];
	//pfd[0].fd = local_fd;
	//pfd[0].events = POLLIN;	
	//char read_buf[1024];
	//char proxied_write[1024] = {0};
	//char write_buf[] = "Modified read\n";		
	struct user_regs_struct regs;
	//struct ptrace_syscall_info syscall_info;
	char * data_to_write = "MODIFIED WRITE OPERATION\n";
	long new_remote_buf = call(pid, LIB_C_STR, calloc_ptr, 1, DATA_MAX_LEN);
	

	printf("Allocated %d bytes at %p\n", DATA_MAX_LEN, (void *) new_remote_buf);
	ptrace(PTRACE_ATTACH, pid, 0, 0);
	waitpid(pid, 0, WSTOPPED);
	
	putdata(pid, new_remote_buf, data_to_write, strlen(data_to_write + 1));
	/**
	printf("Waiting for syscall\n");
		if(ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
			perror("Error getting system call");
			printf("Errno: %d\n",errno);			
		}
		waitpid(pid, 0, WSTOPPED);
	**/
	printf("waiting for system call\n\n");
	while(1) {			
		if(ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
			perror("Error getting system call");
			printf("Errno: %d\n",errno);
			continue;
		}
		waitpid(pid, 0, WSTOPPED);
		ptrace(PTRACE_GETREGS, pid, 0, &regs);
		// retreive the system call number
		long syscall = regs.orig_rax;        
		
        	
		
		switch(syscall) {
			case SYS_read:
				printf("Caught call to read()\n");				
				break;
			case SYS_write:				
				if(regs.rdi == target_fd) {
					fprintf(stdout, "Registers: rdi: %ld, rsi: %ld (%p), rdx: %ld\n",
						(long)regs.rdi, (long)regs.rsi, (void *)regs.rsi, (long)regs.rdx);
					printf("Target proc attempting to write %llu bytes from %p\n", regs.rdx, (void *) regs.rsi);
					void * remote_buf = (void *)regs.rsi;
					printf("Pointer to remote buffer: %p\n",remote_buf);
					long to_read = (long) regs.rdx;
					// allocate space for the string we are reading and add enough flex space at the end to account for extra unneeded data
					int bufsize = to_read + sizeof(long);
					char * copied_data = malloc(bufsize);										
					bzero(copied_data, bufsize);
					printf("allocated buffer of %d bytes\n", bufsize);

					int copied;
					long data = 0;
					
					printf("Attempting to peek remote buffer\n");
					for (copied = 0; to_read > 0; copied += sizeof(data)){
						data = ptrace(PTRACE_PEEKDATA, pid, remote_buf + copied, 0);
						if(data == -1) {
							perror("PEEK_DATA ERROR");
							break;
						}
						printf("copying %ld bytes to %p\n", sizeof(data), copied_data + copied);						
						memcpy(copied_data + copied, &data, sizeof(data));
						to_read -= sizeof(data);
						printf("Copied: %s\n",copied_data + copied);
						//printf("%ld bytes left to read\n",to_read);
								
					}
					printf("Target proc wanted to write: %s\n", copied_data);					

					// modify the target process' register (rsi) to point to the new buffer instead of the old
					regs.rsi = new_remote_buf;
					regs.rdx = strlen(data_to_write) + 1;
					if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
						perror("PTRACE_SETREGS error");
					} 
					// print new register values
					ptrace(PTRACE_GETREGS, pid, 0, &regs);

					fprintf(stdout, "Registers: rdi: %ld, rsi: %ld, rdx: %ld\n",
						(long)regs.rdi, (long)regs.rsi, (long)regs.rdx);
					printf("New write argument is %p\n", (void *) regs.rsi);
					// allow remote process execution to continue
					ptrace(PTRACE_SYSCALL, pid, 0, 0);
					waitpid(pid, 0, WSTOPPED);
					// should be stopped at syscall exit now, let's expect return values
					ptrace(PTRACE_GETREGS, pid, 0, &regs);
					printf("syscall returned: %ld\n\n\n", (long)regs.rax);
					//ptrace(PTRACE_CONT, pid, 0, 0);
				}
				break;
			default:
				break;
		}
		
	}
	return 0;
}

