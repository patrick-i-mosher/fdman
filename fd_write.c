#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {
    char* path = "/home/parsons/tmp/fdtest.bin";
    char* buf = "Written from writer\n";
    FILE* file = NULL;
    int fd = 0;    
    //pid_t pid = 0;
    
    file = fopen(path, "w+");
    fd = fileno(file);
    //pid = getpid();
    while(1) {
        printf("PID: %d :: Open FD: %d\n", getpid(), fd);       
        if (write(fd, buf, strlen(buf)) <= 0) {
            // failed to write to file
            if(fd == 01){
                perror("Failed to write to file: ");
            }    
            else {
                printf("Wrote to file");
            }    
        return 1;
    }

        sleep(1);
    }
}