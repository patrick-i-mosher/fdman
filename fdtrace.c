#include "fdtrace.h"

#define DATA_MAX_LEN 1024

#define USAGE																  	  \
	"usage:\n"                                                                    \
	"  fdtrace [options]\n"                                                       \
	"options:\n"                                                                  \
	"  -h                  Show this help message.\n"                             \
	"  -p [process_id]     Target process ID\n"                                   




struct option gLongOptions[] = {
	{"pid",           required_argument,      NULL,           'p'},
	{"help",          no_argument,            NULL,           'h'},
	{NULL,            0,                      NULL,             0}
};

void init(int argc, char** argv) {

	gen_ctx = NULL;
	write_ctx = NULL;
	read_ctx = NULL;
	file_ctx = NULL;
	long pid = parse_args(argc, argv);
	init_general_context(pid);	
	init_write_context();
	init_read_context();
	init_file_context();
}

void terminate() {
	int fatal_error = gen_ctx->fatal_error;	
	release_file_context();
	release_read_context();
	release_write_context();
	release_general_context();
	if (fatal_error) {
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}

void intercept_write() {
	parse_sys_write_registers();	
	peek_remote_buffer();
	modify_sys_write_registers();		
}

void init_file_context() {
	file_ctx = calloc(1, sizeof(file_context));
	file_ctx->target_file = "/home/parsons/tmp/fdtest"; 	
	file_ctx->dir = NULL;				
	file_ctx->entry = malloc(sizeof(struct dirent));
	file_ctx->stat_buf = malloc(sizeof(struct stat));
	file_ctx->proc_path = calloc(1, PATH_MAX);
	snprintf(file_ctx->proc_path, PATH_MAX, "/proc/%ld/fd", gen_ctx->pid);	
	file_ctx->dir = opendir(file_ctx->proc_path);
}
void init_general_context(long pid) {	
	gen_ctx = calloc(1, sizeof(general_context));
	gen_ctx->pid = pid;	
	gen_ctx->regs = NULL;
	gen_ctx->calloc_ptr = (void *)&calloc;
	gen_ctx->target_fd = -1;
	gen_ctx->fatal_error = 0;	
}

void init_write_context(void) {
	write_ctx = calloc(1, sizeof(write_context));
	write_ctx->data_to_write = "MODIFIED WRITE OPERATION\n";
	write_ctx->sys_write_args.sys_write_fd = 0;
	write_ctx->sys_write_args.sys_write_buf_addr = 0;
	write_ctx->sys_write_args.sys_write_count = 0;
	write_ctx->write_replacement_buf_addr = call(gen_ctx->pid, LIB_C_STR, gen_ctx->calloc_ptr, 1, DATA_MAX_LEN);
	putdata(gen_ctx->pid, write_ctx->write_replacement_buf_addr, write_ctx->data_to_write, strlen(write_ctx->data_to_write + 1));	
}

void init_read_context() {
	read_ctx = calloc(1, sizeof(read_context));
}

int parse_args(int argc, char** argv) {
	int c;
	long pid = -1;
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
				pid = -1;
			}
			if (pid < 0) {
				fprintf(stderr, "cannot accept negative pids\n");
				pid = -1;
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
			pid = -1;
			break;
		default:
			pid = -1;
		}
	}
	if (pid == -1) {
		fprintf(stderr, "must specify a remote process with -p\n");
		
	}
	return pid;
}

void release_file_context(){
	if(file_ctx == NULL) {
		return;
	}
	if(file_ctx->dir != NULL) {
		closedir(file_ctx->dir);
	}
	if(file_ctx->proc_path != NULL) {
		free(file_ctx->proc_path);
	}
	if(file_ctx->entry != NULL) {
		free(file_ctx->entry);
	}
	if(file_ctx->stat_buf != NULL) {
		free(file_ctx->stat_buf);
	}

	free(file_ctx);
}

void release_read_context() {
	if(read_ctx == NULL) {
		return;
	}
	free(read_ctx);
}

void release_write_context() {
	if(write_ctx == NULL) {
		return;
	}
	free(write_ctx);

}

void release_general_context() {
	if(gen_ctx == NULL) {
		return;
	}
	free(gen_ctx);
}

void scan_fd() {
	while((file_ctx->entry = readdir(file_ctx->dir))) {
		bzero(file_ctx->stat_buf, sizeof(struct stat));
		bzero(file_ctx->proc_path, PATH_MAX);
		snprintf(file_ctx->proc_path, PATH_MAX, "/proc/%ld/fd/%s",gen_ctx->pid, file_ctx->entry->d_name);
		if(lstat(file_ctx->proc_path, file_ctx->stat_buf) == -1) {
			perror("Error occurred reading file");			
			continue;
		}
		if(S_ISLNK(file_ctx->stat_buf->st_mode)) {
			char* slink_target = NULL;
			slink_target = malloc(PATH_MAX);
			ssize_t link_len = readlink(file_ctx->proc_path, slink_target, PATH_MAX);
			if( link_len == -1){
				perror("Error reading target link");
				continue;
			}
			if(strncmp(slink_target, file_ctx->target_file, link_len) == 0){				
				gen_ctx->target_fd = atoi(file_ctx->entry->d_name);				
			}
			free(slink_target);
		}
	}
	return;
}

void peek_remote_buffer() {
	long to_read = (long) gen_ctx->regs->rdx;	
	int bufsize = to_read + sizeof(long);
	int copied;
	long data = 0;	
	void * original_write_source_buf = (void *)gen_ctx->regs->rsi;	
	char * copied_data_buf = calloc(1, bufsize);	
	for (copied = 0; to_read > 0; copied += sizeof(data)){
		data = ptrace(PTRACE_PEEKDATA, gen_ctx->pid, original_write_source_buf + copied, 0);
		if(data == -1) {
			perror("PEEK_DATA ERROR");
			break;
		}		
		memcpy(copied_data_buf + copied, &data, sizeof(data));
		to_read -= sizeof(data);
	}
	printf("Target proc wanted to write: %s\n", copied_data_buf);	
	free(copied_data_buf);
	return;
}

void parse_sys_write_registers() {
	write_ctx->sys_write_args.sys_write_fd = gen_ctx->regs->rdi;
	write_ctx->sys_write_args.sys_write_buf_addr = gen_ctx->regs->rsi;
	write_ctx->sys_write_args.sys_write_count = gen_ctx->regs->rdx;
}

void modify_sys_write_registers() {
	gen_ctx->regs->rsi = write_ctx->write_replacement_buf_addr;
	gen_ctx->regs->rdx = strlen(write_ctx->data_to_write) + 1;
	if(ptrace(PTRACE_SETREGS, gen_ctx->pid, NULL, gen_ctx->regs) == -1) {
		perror("PTRACE_SETREGS error");
	} 
}