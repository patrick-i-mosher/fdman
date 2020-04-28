
#include "fdtrace.h"

int main(int argc, char** argv) {
	init(argc, argv);	
	scan_fd();		
	ptrace(PTRACE_ATTACH, gen_ctx->pid, 0, 0);
	waitpid(gen_ctx->pid, 0, WSTOPPED);
	
	while(1) {			
		if(ptrace(PTRACE_SYSCALL, gen_ctx->pid, 0, 0) == -1) {
			perror("Error getting system call");
			printf("Errno: %d\n",errno);
			continue;
		}
		waitpid(gen_ctx->pid, 0, WSTOPPED);
		ptrace(PTRACE_GETREGS, gen_ctx->pid, 0, &gen_ctx->regs);
		// retreive the system call number
		long syscall = gen_ctx->regs->orig_rax;             			
		if(gen_ctx->regs->rdi == gen_ctx->target_fd) {
			switch(syscall) {
				case SYS_read:
					//TO DO								
					break;
				case SYS_write:									
					intercept_write();
					ptrace(PTRACE_SYSCALL, gen_ctx->pid, 0, 0);
					waitpid(gen_ctx->pid, 0, WSTOPPED);					
					break;
				default:
					break;
			}
		}
	}		
	
	return 0;
}










