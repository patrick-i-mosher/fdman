#include "fdtools.h"

void scan_fd(DIR * dir, steque_t * queue, int target_pid) {
	
	struct dirent * entry = malloc(sizeof(struct dirent));
	struct stat * stat_buf = malloc(sizeof(struct stat));
	char * proc_path = malloc(PATH_MAX);
	while((entry = readdir(dir))) {
		bzero(stat_buf, sizeof(struct stat));
		bzero(proc_path, PATH_MAX);
		snprintf(proc_path, PATH_MAX, "/proc/%d/fd/%s",target_pid, entry->d_name);
		if(lstat(proc_path, stat_buf) == -1) {
			perror("Error occurred reading file");			
			continue;
		}
		if(S_ISLNK(stat_buf->st_mode)) {
			char* target_fd = NULL;
			target_fd = malloc(PATH_MAX);
			if(readlink(proc_path, target_fd, PATH_MAX) == -1){
				perror("Error reading target link");
				continue;
			}
			steque_enqueue(queue, (char *) target_fd);			
		}
	}
	free(entry);
	free(stat_buf);
	free(proc_path);
	return;
}