#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

void do_write() {
    // Writes message to stdout then sleeps      
    
    int fd = open("/home/parsons/Dev/fdman/fdtest.txt", O_NONBLOCK | O_WRONLY);
    //int read_fd = open("/dev/urandom", O_RDONLY);
    if(fd == -1) {
        perror("Error opening file");
        return;
    }
    
    printf("obtained handle with fd %d\n", fd);
    char * buf = malloc(20);    
    printf("Write buffer address: %p\n", buf);
    while(1) {        
        if(errno) {
            perror("Error");
            printf("FD: %d\n",fd);
            errno = 0;
        }
        else {
            //printf("Writing to fd %d\n", fd);               
            snprintf(buf, 20, "write test\n");            
            if(write(fd, buf, strlen(buf)) == -1) {
                char err_str[1024] = {0};
                snprintf(err_str, 1024, "Write error fd %d", fd);
                perror(err_str);
                errno = 0;
            }
            sleep(1);            
        }
    }
    close(fd);
    //close(read_fd);
    free(buf);    
}

void do_read() {
    int fd = open("/home/parsons/tmp/fdtest", O_RDONLY);
    //int read_fd = open("/dev/urandom", O_RDONLY);
    if(fd == -1) {
        perror("Error opening file");
        return;
    }
    
    printf("obtained handle with fd %d\n", fd);
    char * buf = malloc(20);        
    while(1) {        
        if(errno) {
            perror("Error");
            errno = 0;
        }
        else {       
            
            if(read(fd, buf, 20) == -1){
                perror("Read Error");                
                errno = 0;
            }
            else {
                printf("Read from file: %s\n", buf);
            }
        }
        
        // do a read from stdin       
        sleep(1);
    }
    close(fd);
    //close(read_fd);
    free(buf);   
}

int main(int argc, char** argv) {    
    
    int pid = getpid();
    printf("PID: %d\n", pid);
    printf("SYS_write number: %d\n", SYS_write);
    printf("SYS_read number: %d\n", SYS_read);

    // big brain arg parsing
    if(strcmp(argv[1], "w") == 0) {
        do_write();
    }
    else {
        do_read();
    }
    return 1;
}