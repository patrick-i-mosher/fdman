#include "libprocinfo.h"

pid_t get_proc_id() {
	return getpid();
}

extern void print_proc_info() {
	printf("PID : %d\n", get_proc_id());
}