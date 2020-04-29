#include "fdtrace.h"

int main(int argc, char** argv) {
	init(argc, argv);	
	scan_fd();		
	if (ptrace(PTRACE_ATTACH, gen_ctx->pid, 0, 0) == -1) {
		write_log("FATAL ERROR", __FILE__, __LINE__, strerror(errno));
		terminate();
	}
	waitpid(gen_ctx->pid, 0, WSTOPPED);
	int i = 0;
	while(1) {			
		printf("%d\n",i);
		i++;
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
		if(gen_ctx->regs->rdi == gen_ctx->target_fd) {
			switch(syscall) {
				case SYS_read:
					//TO DO								
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
	return 0;
}










