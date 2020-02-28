#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

int main(int argc, char** argv) {    
    // Writes message to stdout then sleeps
    int pid = getpid();    
    int fd = open("/dev/pts/4", O_NONBLOCK | O_RDWR);
    if(fd == -1) {
        perror("Error opening file");
        return 1;
    }
    
    printf("obtained handle with fd %d\n", fd);
    char * buf = malloc(20);
    char * buf2 = malloc(20);    
    //struct pollfd pfd[1];
	//pfd[0].fd = fd;
	//pfd[0].events = POLLIN;	
    printf("PID: %d\n", pid);
    while(1) {        
        if(errno) {
            perror("Error:");
            errno = 0;
        }
        else {
            // write to file
            
            printf("Writing to fd %d\n", fd);            
            snprintf(buf, 20, "PID: %d\n", pid);            
            if(write(fd, buf, 20) == -1) {
                perror("Write error");
                errno = 0;
            }
            
            // read from file and print to stdout
            // wait for a response
            //poll(pfd, 1, 1000);
            sleep(1);
            if(read(fd, buf2, 20) == -1){
                if(errno != EWOULDBLOCK) {
                    perror("Read Error");
                }
                errno = 0;
            }
            else {
                printf("Read from file: %s\n", buf2);
            }
            
            
        }
        
        // do a read from stdin       
        sleep(1);
    }
    close(fd);
    
}