
#include <getopt.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
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
	//enum { pipe_read, pipe_write};
	char * read_fifo_path = "/tmp/read_pipe";
	char * write_fifo_path = "/tmp/write_pipe";
	if(mkfifo(read_fifo_path, 0666) == -1) {
		// local process will read from this pipe
		perror("Error creating read FIFO: ");
		if(errno != EEXIST) {
			return 1;
		}
		
	} 
	if(mkfifo(write_fifo_path, 0666) == -1) {
		// local process will write to this pipe	
		perror("Error creating write FIFO: ");
		if(errno != EEXIST) {
			return 1;
		}
	} 
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
	// Call open() in remote process to get handles to our named pipes
	
	// First allocate memory in remote process to store fifo path
	void * ptr = (void *)&calloc;
	long remote_read_addr = call(pid, LIB_C_STR, ptr, 2, 1, strlen(read_fifo_path));
	printf("Allocated memory at %p for read path\n", (void *) remote_read_addr);
	printf("Address of local read path string is %p\n",&read_fifo_path);
	// Write our string to the remotely allocated memory
	
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	waitpid(pid, 0, WSTOPPED);
	//putdata(pid_t child, long addr,
             //char *str, int len)
	putdata(pid, remote_read_addr, read_fifo_path, strlen(read_fifo_path) +1);

	//if(ptrace(PTRACE_POKEDATA, pid, (void*) remote_read_addr, (void *)read_fifo_path) == -1){
	//	perror("Unable to poke data");
	//}	
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	
	long res = ptrace(PTRACE_PEEKDATA, remote_read_addr, NULL);
	printf("Peek results: 0x%lX\n", res);	
	// do it again for the other pipe
	long remote_write_addr = call(pid, LIB_C_STR, ptr, 2, 1, strlen(write_fifo_path));
	printf("Allocated memory at %p for write path\n", (void *) remote_write_addr);
	//ptrace(PTRACE_POKEDATA, pid, (void*) remote_write_addr, write_fifo_path);
	// DEBUG
	
	
	// Make the calls to open()
	int local_read_fd = open(read_fifo_path, O_RDONLY | O_NONBLOCK);
	int local_write_fd = open(write_fifo_path, O_WRONLY | O_NONBLOCK);
	printf("Opened local handles to pipes: %d and %d\n",local_read_fd, local_write_fd);
	ptr = (void *)&open;
	long remote_read_fd = call(pid, LIB_C_STR, ptr, 2, remote_read_addr, O_WRONLY);  // will read locally, write remotely
	printf("Opened read_pipe with fd %ld\n", remote_read_fd);
	long remote_write_fd = call(pid, LIB_C_STR, ptr, 2, remote_write_addr, O_RDONLY); // will write locally, read remotely
	printf("Opened write_pipe with fd %ld\n", remote_write_fd);

	// Check open file descriptors again to verify pipe creation
	dir = opendir(proc_path);
	if(!dir) {
		perror("Unable to open target directory");
		return 1;
	}
	scan_fd(dir, &queue, pid);	
	printf("Found %d open file descriptors\n",steque_size(&queue));
	while(!steque_isempty(&queue)) {
		char * temp = NULL;
		temp = steque_pop(&queue);
		printf("Following file open: %s\n", temp);
		free(temp);		
	}
	closedir(dir);
	// Call dup2 in remote process
	// for now, for testing, we are going to re-direct victim's stdout to another file it has open, fd 3
	ptr = (void*)&dup2;
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

