
#include <getopt.h>
#include <stdio.h>
#include <sys/types.h>
#include "steque.h"
#include "call_x86.h"
#include "fdtools.h"
/**
 * Usage: fdswap <PID> <Underlying Target>
 * Example: fdswap 23445 /dev/null 
 */

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
	char * target_file = "/dev/pts/2"; // my test terminal
	//char * redirect_file = "/dev/pts/4"; // my other test terminal
	DIR * dir = NULL;		
	
	steque_init(&queue);
	// enumerate target process' open file descriptors
	char proc_path[PATH_MAX];
	snprintf(proc_path, PATH_MAX, "/proc/%ld/fd", pid);
	dir = opendir(proc_path);
	if(!dir) {
		perror("Unable to open target directory");
		return 1;
	}
	// identify fd(s) to replace with dup2
	scan_fd(dir, &queue, pid);	
	while(!steque_isempty(&queue)) {
		char * temp = NULL;
		temp = steque_pop(&queue);
		printf("Following file open: %s\n", temp);
		free(temp);		
	}
	closedir(dir);
	printf("%s\n",target_file);
	// Call open in remote process to get a handle on our local file descriptor
	// Call dup2 in remote process
	// for now, for testing, we are going to re-direct victim's stdout to another file it has open, fd 3
	void * ptr = (void*)&dup2;
	printf("My dup2: %p\n",ptr);
	call(pid, "/libc-2", ptr, 2, 3, 1);

	//fprintf_process(pid);
	// attach to target process
	//start_trace(target_pid);
	

	/**
	int newfd = myDup2(3,4);
	char buf[1024] = {0};
	read(4, &buf, 1024);
	printf("new fd: %d, buf: %s\n",newfd, buf);
	end_trace();	
**/
	// replace targeted fd(s)
	// read / write as desired.
	// clean up / free mallocs

	return 0;
}

