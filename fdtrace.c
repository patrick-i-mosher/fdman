#include "fdtrace.h"

static void init_general_context();	
static void init_file_context();
static void init_write_context();
static void init_read_context();
static void release_file_context();
static void release_write_context();
static void release_read_context();
static void release_general_context();
static int parse_args( int argc, char** argv);
static void peek_remote_buffer(void * remote_buf_addr);
static void parse_sys_write_registers();
static void modify_sys_write_registers();

#define DATA_MAX_LEN 1024
#define LOG_MAX 69 // NICE
#define LOG_PATH "/home/parsons/Dev/fdman/fdtrace.log"
#define USAGE																  	  \
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

void init(int argc, char** argv) {
	gen_ctx = NULL;
	write_ctx = NULL;
	read_ctx = NULL;
	file_ctx = NULL;
	long pid = parse_args(argc, argv);
	if(pid == -1) {
		write_log("FATAL ERROR", __FILE__, __LINE__, "must specify a remote process with -p\n");
		gen_ctx->fatal_error = 1;
		terminate();
	}
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
	write_log("INFO", __FILE__, __LINE__, "Terminating Execution");
	if (fatal_error) {
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}

void intercept_write() {
	parse_sys_write_registers();	
	peek_remote_buffer((void*) gen_ctx->regs->rsi);	
	modify_sys_write_registers();			
}

void scan_fd() {
	while((file_ctx->entry = readdir(file_ctx->dir))) {
		bzero(file_ctx->stat_buf, sizeof(struct stat));
		bzero(file_ctx->proc_path, PATH_MAX);
		snprintf(file_ctx->proc_path, PATH_MAX, "/proc/%ld/fd/%s",gen_ctx->pid, file_ctx->entry->d_name);
		if(lstat(file_ctx->proc_path, file_ctx->stat_buf) == -1) {
			write_log("ERROR", __FILE__, __LINE__, strerror(errno));
			continue;
		}
		if(S_ISLNK(file_ctx->stat_buf->st_mode)) {
			char* slink_target = NULL;
			slink_target = malloc(PATH_MAX);
			ssize_t link_len = readlink(file_ctx->proc_path, slink_target, PATH_MAX);
			if( link_len == -1){
				write_log("ERROR", __FILE__, __LINE__, strerror(errno));				
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

void write_log(char * log_level, char * err_file, int line_number, char * log_str) {
	char * logline = calloc(1, LOG_MAX);
	snprintf(logline, LOG_MAX, "%s %s:%d: %s\n", log_level, err_file, line_number, log_str);
	write(gen_ctx->log_file, logline, strlen(logline));
	free(logline);
}

static void init_file_context() {
	file_ctx = calloc(1, sizeof(file_context));
	file_ctx->target_file = "/home/parsons/tmp/fdtest"; 	
	file_ctx->dir = NULL;				
	file_ctx->entry = calloc(1, sizeof(struct dirent));
	file_ctx->stat_buf = calloc(1, sizeof(struct stat));
	file_ctx->proc_path = calloc(1, PATH_MAX);
	snprintf(file_ctx->proc_path, PATH_MAX, "/proc/%ld/fd", gen_ctx->pid);	
	file_ctx->dir = opendir(file_ctx->proc_path);
	if (file_ctx->dir == NULL) {
		write_log("FATAL ERROR", __FILE__, __LINE__, strerror(errno));
		gen_ctx->fatal_error = 1;
		terminate();
	}

}

static void init_general_context(long pid) {	
	gen_ctx = calloc(1, sizeof(general_context));
	gen_ctx->pid = pid;	
	gen_ctx->regs = calloc(1, sizeof(struct user_regs_struct));
	gen_ctx->calloc_ptr = (void *)&calloc;
	gen_ctx->target_fd = -1;
	gen_ctx->fatal_error = 0;
	gen_ctx->log_file = open(LOG_PATH, O_CREAT | O_WRONLY, 0777);
}

static void init_write_context(void) {
	write_ctx = calloc(1, sizeof(write_context));
	write_ctx->data_to_write = "MODIFIED WRITE OPERATION\n";
	write_ctx->sys_write_args.sys_write_fd = 0;
	write_ctx->sys_write_args.sys_write_buf_addr = 0;
	write_ctx->sys_write_args.sys_write_count = 0;
	// Allocate memory in remote process and store write string there
	write_ctx->write_replacement_buf_addr = call(gen_ctx->pid, LIB_C_STR, gen_ctx->calloc_ptr, 1, DATA_MAX_LEN);
	if(write_ctx->write_replacement_buf_addr == 0) {
		write_log("FATAL_ERROR", __FILE__, __LINE__, "Unable to allocate buffer in remote process\n");
		gen_ctx->fatal_error = 1;
		terminate();
	}
	poke_remote_buffer(write_ctx->write_replacement_buf_addr, write_ctx->data_to_write);	
}

static void init_read_context() {
	read_ctx = calloc(1, sizeof(read_context));
}

static int parse_args(int argc, char** argv) {
	int c;
	long pid = -1;
	opterr = 0;
	while ((c = getopt_long(argc, argv, "hp:", gLongOptions, NULL)) != -1) {
		switch (c) {
		case 'h':
			write_log("INFO", __FILE__, __LINE__, USAGE);			
			terminate();
			break;
		case 'p':
			pid = strtol(optarg, NULL, 10);
			if ((errno == ERANGE && (pid == LONG_MAX || pid == LONG_MIN)) ||
				(errno != 0 && pid == 0)) {
				write_log("FATAL ERROR", __FILE__, __LINE__, "Invalid PID provided\n");				
				gen_ctx->fatal_error = 1;
				pid = -1;
			}
			if (pid < 0) {
				write_log("FATAL ERROR", __FILE__, __LINE__, "Cannot accept negative pids\n");				
				pid = -1;
			}
			break;
		case '?':
			if (optopt == 'p') {
				write_log("FATAL ERROR", __FILE__, __LINE__, "Option -p requires an argument.\n");								
			} else if (isprint(optopt)) {
				write_log("FATAL ERROR", __FILE__, __LINE__, "Unknown option\n");												
			} else {
				write_log("FATAL ERROR", __FILE__, __LINE__, "Unknown option character\n");												
			}
			pid = -1;
			break;
		default:
			pid = -1;
		}
	}
	if (pid == -1) {
		write_log("FATAL ERROR", __FILE__, __LINE__, "must specify a remote process with -p\n");								
	}
	return pid;
}

static void release_file_context(){
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

static void release_read_context() {
	if(read_ctx == NULL) {
		return;
	}
	free(read_ctx);
}

static void release_write_context() {
	if(write_ctx == NULL) {
		return;
	}
	free(write_ctx);

}

static void release_general_context() {
	if(gen_ctx == NULL) {
		return;
	}
	close(gen_ctx->log_file);
	free(gen_ctx);
}

static void peek_remote_buffer(void * remote_buf_addr) {
	long to_read = (long) gen_ctx->regs->rdx;	
	int bufsize = to_read + sizeof(long);
	int copied;
	long data = 0;		
	char * copied_data_buf = calloc(1, bufsize);	
	for (copied = 0; to_read > 0; copied += sizeof(data)){
		data = ptrace(PTRACE_PEEKDATA, gen_ctx->pid, remote_buf_addr + copied, 0);
		if(data == -1) {
			perror("PEEK_DATA ERROR");
			break;
		}		
		memcpy(copied_data_buf + copied, &data, sizeof(data));
		to_read -= sizeof(data);
	}
	printf("Remote Buffer Contents: %s\n", copied_data_buf);	
	free(copied_data_buf);
	return;
}

static void poke_remote_buffer(long remote_buf_addr, char *data_to_write) {
	int	copied_blocks = 0;
	int blocks_to_copy = strlen(data_to_write) / sizeof(long);
	while(copied_blocks < blocks_to_copy) {		
		ptrace(PTRACE_POKEDATA, gen_ctx->pid, remote_buf_addr, data_to_write);      
		remote_buf_addr += sizeof(long);
		data_to_write += sizeof(long);
		++copied_blocks;
	}
	int bytes_left = strlen(data_to_write) % sizeof(long);
	if(bytes_left != 0) {		
		ptrace(PTRACE_POKEDATA, gen_ctx->pid, remote_buf_addr, data_to_write);      
	}
}


static void parse_sys_write_registers() {
	write_ctx->sys_write_args.sys_write_fd = gen_ctx->regs->rdi;
	write_ctx->sys_write_args.sys_write_buf_addr = gen_ctx->regs->rsi;
	write_ctx->sys_write_args.sys_write_count = gen_ctx->regs->rdx;
}

static void modify_sys_write_registers() {
	gen_ctx->regs->rsi = write_ctx->write_replacement_buf_addr;
	gen_ctx->regs->rdx = strlen(write_ctx->data_to_write) + 1;
	if(ptrace(PTRACE_SETREGS, gen_ctx->pid, NULL, gen_ctx->regs) == -1) {
		perror("PTRACE_SETREGS error");
	} 
}