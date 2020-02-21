#include <dirent.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "steque.h"

/**
 * Usage: fdswap <PID> <Underlying Target>
 * Example: fdswap 23445 /dev/null 
 */
int main(int argc, char** argv) {
	steque_t queue;
	int target_pid = 0;
	int fd_count = 0;
	DIR * dir = NULL;
	
	bzero(dir);	
	// TO DO: parse args to get target process number
	target_pid = atoi(argv[1]);
	//TO DO: Error checking
	steque_ini(&queue);
	// enumerate target process' open file descriptors
	char proc_path[PATH_MAX];
	snprintf(proc_path, PATH_MAX, "/proc/%d/fd",target_pid);
	dir = opendir(proc_path);
	if(!dir) {
		perror("Unable to open target directory");
		return 1;
	}
	// identify fd(s) to replace with dup2
	scan_fd(dir, &queue, target_pid);	
	// replace targeted fd(s)
	// read / write as desired.
	// clean up / free mallocs
}

void scan_fd(DIR * dir, steque_t * queue, int target_pid) {
	
	struct dirent * entry = malloc(sizeof(struct dirent));
	struct stat * stat_buf = malloc(sizeof(struct stat));
	char * proc_path = malloc(PATH_MAX);
	while((entry = readdir(dir))) {
		bzero(stat_buf);
		bzero(proc_path);
		snprintf(proc_path, PATH_MAX, "/proc/%d/fd/%s",target_pid, entry->d_name);
		if(lstat(proc_path, stat_buf) == -1) {
			perror("Error occurred reading file");			
			continue;
		}
		if(S_ISLNK(stat_buf->st_mode)) {
			char* target_fd = malloc(strlen(proc_path));
			if(readlink(proc_path, target_fd, PATH_MAX) == -1){
				perror("Error reading target link");
				continue;
			}
			steque_push(&queue, target_fd);			
		}
	}
	free(entry);
	free(stat_buf);
	free(proc_path);
	return;
}