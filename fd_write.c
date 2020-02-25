#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {    
    // Writes message to stdout then sleeps
    int pid = getpid();
    FILE* file = fopen("/home/parsons/Dev/out.txt", "w+");
    void * ptr = (void*)&dup2;
    printf("My dup2 address: %p\n",ptr);
    while(1) {
        // do a write from stdout
        printf("PID: %d\n", pid);
        // do a read from stdin       
        sleep(1);
    }
    close(fileno(file));
    
}