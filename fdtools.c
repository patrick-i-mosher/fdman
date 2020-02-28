#include "fdtools.h"

// Retrieves a list of open handles to the specified file in the specified process
void scan_fd(DIR * dir, steque_t * queue, int target_pid, char * target_file) {
	
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
			char* slink_target = NULL;
			slink_target = malloc(PATH_MAX);
			ssize_t link_len = readlink(proc_path, slink_target, PATH_MAX);
			if( link_len == -1){
				perror("Error reading target link");
				continue;
			}
			if(strncmp(slink_target, target_file, link_len) == 0){
				int * target_fd = malloc(sizeof(int));
				int fd = atoi(entry->d_name);
				memcpy(target_fd, &fd, sizeof(int));
				steque_enqueue(queue, target_fd);
			}
			free(slink_target);
		}
	}
	free(entry);
	free(stat_buf);
	free(proc_path);
	return;
}