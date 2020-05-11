#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#define USAGE																  	  \
	"usage:\n"                                                                    \
	"  fdtrace [options]\n"                                                       \
	"options:\n"                                                                  \
	"  -h                  Show this help message.\n"                             \
	"  -w                  Write to target file\n"                                \
    "  -f [path]           Path to target file\n"                                 \
    "  -r                  Read from target file\n"   

static struct option gLongOptions[] = {
	{"write",         no_argument,          NULL,           'w'},
    {"read",          no_argument,          NULL,           'r'},
    {"file",          required_argument,    NULL,           'f'},
	{"help",          no_argument,          NULL,           'h'},
	{NULL,            0,                    NULL,             0}
};

void do_write(char * filepath) {
    char * buf = malloc(1024);    
    printf("Write buffer address: %p\n", buf);
    while(1) {        
        int fd = open(filepath, O_NONBLOCK | O_RDWR);    
        if(fd == -1) {
            perror("Error opening file");
            return;
        }
        if(errno) {
            perror("Error");
            printf("FD: %d\n",fd);
            errno = 0;
        }
        else {                  
            snprintf(buf, 1024, "write test\n");            
            if(write(fd, buf, strlen(buf)) == -1) {
                char err_str[1024] = {0};
                snprintf(err_str, 1024, "Write error fd %d", fd);
                perror(err_str);
                errno = 0;
            }
            sleep(1);            
        }
        close(fd);
    }
    free(buf);    
}

void do_read(char * filepath) {
    char * buf = malloc(1024);            
    while(1) {        
        int fd = open(filepath, O_RDWR);    
        if(fd == -1) {
        perror("Error opening file");
        return;
    }    
        if(errno) {
            perror("Error");
            errno = 0;
        }
        else {                               
            int res = read(fd, buf, 1024);
            if(res == -1){
                perror("Read Error");                
                errno = 0;
            }
            else {
                printf("Read %d bytes from file: %s\n", res, buf);
            }
        }            
        bzero(buf, 1024);
        close(fd);   
        sleep(2);
    }         
    free(buf);   
}

int main(int argc, char** argv) {    
    
    int pid = getpid();
    printf("PID: %d\n", pid);
    printf("SYS_write number: %d\n", SYS_write);
    printf("SYS_read number: %d\n", SYS_read);
    char * filepath = NULL;
    int mode = 0;
    int c;
    opterr = 0;
	while ((c = getopt_long(argc, argv, "hwrf:", gLongOptions, NULL)) != -1) {
		switch (c) {		
        case 'h':
            printf("%s", USAGE);
            return 0;
        case 'f': 
            filepath = optarg;
            break;
		case 'w':		
            mode = 'w';
			break;
        case 'r':
            mode = 'r';
            break;
		case '?':
			printf("Unknown option\n%s", USAGE);            
			break;
		default:
			printf("%s", USAGE);
		}
	}
    if (mode != 'w' && mode != 'r') {
        printf("Invalid operation mode %d specified\n%s", mode, USAGE);
        return 1; 
    }
    if (filepath == NULL) {
        printf("You must specify a path to the target file\n%s", USAGE);
        return 1;
    }
    switch(mode) {
        case 'w':
            do_write(filepath);
            break;
        case 'r':
            do_read(filepath);
            break;
        default:
            return 1;
    }
    return 1;
}