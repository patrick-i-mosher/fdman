
#include <getopt.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
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
	steque_t target_file_q;	
	char * target_file = "/dev/pts/4"; // my test terminal
	
	char * fifo_path = "/tmp/read_pipe";
	
	if(mkfifo(fifo_path, 0666) == -1) {
		// local process will read from this pipe
		perror("Error creating FIFO: ");
		if(errno != EEXIST) {
			return 1;
		}		
	} 
	DIR * dir = NULL;			
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
	// identify fd(s) to replace with dup2
	/**
	scan_fd(dir, &queue, pid, target_file);	
	while(!steque_isempty(&queue)) {
		int * temp = NULL;
		temp = steque_pop(&queue);
		printf("Handle to %s: %d\n", target_file, *temp);		
		free(temp);		
	}
	closedir(dir);	
	**/
	// Call open() in remote process to get handles to our named pipes
	
	// First allocate memory in remote process to store fifo path
	void * ptr = (void *)&calloc;
	long remote_read_addr = call(pid, LIB_C_STR, ptr, 2, 1, strlen(fifo_path) +1);
	printf("Allocated memory at %p for FIFO path\n", (void *) remote_read_addr);
	printf("Address of local FIFO path string is %p\n",&fifo_path);	
	// Write our string to the remotely allocated memory
	
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	waitpid(pid, 0, WSTOPPED);	
	putdata(pid, remote_read_addr, fifo_path, strlen(fifo_path) +1);	
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	
	// Make the calls to open()
	ptr = (void *)&open;
	int local_fd = open(fifo_path, O_RDWR | O_NONBLOCK);
	if (local_fd == -1) {
		perror("Error opening local read");
		return 1;
	}
	long remote_fd = call(pid, LIB_C_STR, ptr, 2, remote_read_addr, O_RDWR);
	printf("Opened remote pipe with fd %ld\n", remote_fd);
	printf("Opened local handle to pipe: %d\n",local_fd);	
	// Check open file descriptors again to verify pipe creation
	dir = opendir(proc_path);
	if(!dir) {
		perror("Unable to open target directory");
		return 1;
	}
	scan_fd(dir, &queue, pid, target_file);	
	printf("Found %d open file descriptors\n",steque_size(&queue));
	ptr = (void*)&dup2;	
	while(!steque_isempty(&queue)) {
		int * temp = NULL;
		temp = steque_pop(&queue);
		//printf("Handle to %s: %d\n", target_file, *temp);		
		// redirect output from the original target file to the named pipe
		call(pid, "/libc-2", ptr, 2, remote_fd, *temp);	
		free(temp);		
	}
	closedir(dir);
	int target_fd = open(target_file, O_RDWR);	
	struct pollfd pfd[1];
	pfd[0].fd = local_fd;
	pfd[0].events = POLLIN;	
	char read_buf[1024];
	char proxied_write[1024];
	char write_buf[] = "I'm up in yo guts\n";
	while(1) {		
		poll(pfd, 1, -1);
		switch(pfd[0].revents) {
			// intercept writes and return our own data
			case POLLIN:
				// remote write event
				read(local_fd, read_buf, 1024);
				printf("Caught remote write operations: %s\n",read_buf);	
				// Write our own data to the target file instead
				snprintf(proxied_write, 1024, "Intercepted write: %s\n",read_buf);
				write(target_fd, proxied_write, strlen(proxied_write) + 1);
				write(local_fd, write_buf, strlen(write_buf) + 1);
				sleep(1);
				bzero(read_buf, 1024);
				break;
			// detect read attempt and write to the fifo
			case POLLOUT:
				printf("Caugh read attempt\n");
				write(local_fd, write_buf, strlen(write_buf) + 1);
				break;
			default:
				// POLLERR
				//perror("Poll error");
				break;
		}

	}
	return 0;
}

