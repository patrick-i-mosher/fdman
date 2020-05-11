#include "fdtrace.h"

int main(int argc, char** argv) {
	printf("Running with PID %d\n", getpid());
	init(argc, argv);	
	//scan_fd();		
	if (ptrace(PTRACE_ATTACH, gen_ctx->pid, 0, 0) == -1) {		
		write_log("FATAL ERROR", __FILE__, __LINE__, strerror(errno));
		terminate();
	}
	waitpid(gen_ctx->pid, 0, WSTOPPED);	
	while(1) {							
		if(ptrace(PTRACE_SYSCALL, gen_ctx->pid, 0, 0) == -1) {
			write_log("FATAL ERROR", __FILE__, __LINE__, strerror(errno));
			terminate();
			continue;
		}
		waitpid(gen_ctx->pid, 0, WSTOPPED);
		if(ptrace(PTRACE_GETREGS, gen_ctx->pid, 0, gen_ctx->regs) == -1) {
			write_log("FATAL ERROR", __FILE__, __LINE__, strerror(errno));
			terminate();
		}
		// retreive the system call number
		long syscall = gen_ctx->regs->orig_rax;
		if (syscall == SYS_read || syscall == SYS_write) {
			scan_fd();
			if(gen_ctx->regs->rdi == gen_ctx->target_fd) {
				switch(syscall) {
					case SYS_read:
						intercept_read();					
						break;
					case SYS_write:							
						intercept_write();
						if(ptrace(PTRACE_SYSCALL, gen_ctx->pid, 0, 0) == -1) {
							write_log("FATAL ERROR", __FILE__, __LINE__, strerror(errno));
							terminate();
						}					
						waitpid(gen_ctx->pid, 0, WSTOPPED);					
						break;
					default:
						break;
				}
			}
		}
		
	}			
	return 0;
}










