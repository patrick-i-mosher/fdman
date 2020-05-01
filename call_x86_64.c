
#include "call_x86_64.h"

void *find_library(pid_t pid, const char *libname) {
  static const char *text_area = " r-xp ";
  char filename[32];
  snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
  FILE *f = fopen(filename, "r");
  char *line = NULL;
  size_t line_size = 0;
  while (getline(&line, &line_size, f) >= 0) {
    char *pos = strstr(line, libname);
    if (pos != NULL && strstr(line, text_area)) {
      long val = strtol(line, NULL, 16);
      free(line);
      fclose(f);
      return (void *)val;
    }
  }
  free(line);
  fclose(f);
  return NULL;
}

int poke_text(pid_t pid, void *where, void *new_text, void *old_text,
              size_t len) {
  if (len % sizeof(void *) != 0) {
    printf("invalid len, not a multiple of %zd\n", sizeof(void *));
    return -1;
  }

  long poke_data;
  size_t copied = 0;
  for (copied = 0; copied < len; copied += sizeof(poke_data)) {
    memmove(&poke_data, new_text + copied, sizeof(poke_data));
    if (old_text != NULL) {
      errno = 0;
      long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
      if (peek_data == -1 && errno) {
        perror("PTRACE_PEEKTEXT");
        return -1;
      }
      memmove(old_text + copied, &peek_data, sizeof(peek_data));
    }
    if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
      perror("PTRACE_POKETEXT");
      return -1;
    }
  }
  return 0;
}

void putdata(pid_t child, long addr, char *str, int len) {
  char *laddr;
  int i, j;
  union u {
    long val;
    char chars[sizeof(long)];
  } data;
    i = 0;
    j = len / sizeof(long);
    laddr = str;
    while(i < j) {
      memcpy(data.chars, laddr, sizeof(long));
      ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
      //printf("Wrote %s\n",data.chars);
      ++i;
      laddr += sizeof(long);
    }
    j = len % sizeof(long);
    if(j != 0) {
      memcpy(data.chars, laddr, j);
      ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
      //printf("Wrote %s\n",data.chars);
    }
}

int do_wait(const char *name) {
  int status;
  if (wait(&status) == -1) {
    perror("wait");
    return -1;
  }
  if (WIFSTOPPED(status)) {
    if (WSTOPSIG(status) == SIGTRAP) {
      return 0;
    }
    printf("%s unexpectedly got status %s\n", name, strsignal(status));
    return -1;
  }
  printf("%s got unexpected status %d\n", name, status);
  return -1;
}

int singlestep(pid_t pid) {
  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
    perror("PTRACE_SINGLESTEP");
    return -1;
  }
  return do_wait("PTRACE_SINGLESTEP");
}

void check_yama(void) {
  FILE *yama_file = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
  if (yama_file == NULL) {
    return;
  }
  char yama_buf[8];
  memset(yama_buf, 0, sizeof(yama_buf));
  fread(yama_buf, 1, sizeof(yama_buf), yama_file);
  if (strcmp(yama_buf, "0\n") != 0) {
    printf("\nThe likely cause of this failure is that your system has "
           "kernel.yama.ptrace_scope = %s",
           yama_buf);
    printf("If you would like to disable Yama, you can run: "
           "sudo sysctl kernel.yama.ptrace_scope=0\n");
  }
  fclose(yama_file);
}

int32_t compute_jmp(void *from, void *to) {
  int64_t delta = (int64_t)to - (int64_t)from - REL32_SZ;
  if (delta < INT_MIN || delta > INT_MAX) {
    printf("cannot do relative jump of size %li; did you compile with -fPIC?\n",
           delta);
    exit(1);
  }
  return (int32_t)delta;
}

int attach_process(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
        perror("PTRACE_ATTACH");
        check_yama();
        return -1;
    }  
    if (waitpid(pid, 0, WSTOPPED) == -1) {
        perror("wait");
        return -1;
    }
}
int save_register_state(pid_t pid, struct user_regs_struct * register_save_state) {        
    if (ptrace(PTRACE_GETREGS, pid, NULL, register_save_state)) {
        perror("PTRACE_GETREGS");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
}
void * syscall_mmap(call_x86_64_context * call_ctx) { 
    void *rip = (void *)call_ctx->register_save_state->rip;
    memmove(call_ctx->newregs, call_ctx->register_save_state, sizeof(struct user_regs_struct));
    call_ctx->newregs->rax = SYS_mmap;                    // mmap
    call_ctx->newregs->rdi = 0;                           // addr
    call_ctx->newregs->rsi = PAGE_SIZE;                   // length
    call_ctx->newregs->rdx = PROT_READ | PROT_EXEC;       // prot
    call_ctx->newregs->r10 = MAP_PRIVATE | MAP_ANONYMOUS; // flags
    call_ctx->newregs->r8 = -1;                           // fd
    call_ctx->newregs->r9 = 0;                            //  offset
    
    call_ctx->new_word[0] = 0x0f; // SYSCALL
    call_ctx->new_word[1] = 0x05; // SYSCALL
    call_ctx->new_word[2] = 0xff; // JMP %rax
    call_ctx->new_word[3] = 0xe0; // JMP %rax

    // insert the SYSCALL instruction into the process, and save the old word
    if (poke_text(call_ctx->pid, rip, call_ctx->new_word, call_ctx->old_word, sizeof(call_ctx->new_word))) {
        return NULL;
    }
    // set the new registers with our syscall arguments
    if (ptrace(PTRACE_SETREGS, call_ctx->pid, NULL, call_ctx->newregs)) {
        perror("PTRACE_SETREGS");
        return NULL;
    }
    // invoke mmap(2)
    if (singlestep(call_ctx->pid)) {
        return NULL;
    }
    // read the new register state, so we can see where the mmap went
    if (ptrace(PTRACE_GETREGS, call_ctx->pid, NULL, call_ctx->newregs)) {
        perror("PTRACE_GETREGS");
        return -1;
    }
    // this is the address of the memory we allocated    
    if ((void *)call_ctx->newregs->rax == (void *)-1) {        
        return NULL;
    }
    else {
        return (void *)call_ctx->newregs->rax;
    }
}
call_x86_64_context * init_call_context(pid_t pid) {
    call_x86_64_context * call_ctx = calloc(sizeof(call_x86_64_context));
    call_ctx->pid = pid;    
    call_ctx->remote_libc_addr = find_library(call_ctx->pid, LIB_C_STR);
    call_ctx->local_libc_addr = find_library(getpid(), LIB_C_STR);
    call_ctx->format = "instruction pointer = %p\n";
    call_ctx->register_save_state = calloc(1, sizeof(struct user_regs_struct));
    call_ctx->newregs = calloc(1, sizeof(struct user_regs_struct));
    return call_ctx;
}

long call(call_x86_64_context * call_ctx, void *local_function, int nargs, ...) {      
    if (attach_process(call_ctx->pid) == -1) {
        return -1;
    }
    
    if(save_register_state(call_ctx->pid, call_ctx->register_save_state) == -1) {
        return -1;
    }  
    void * mmap_memory = syscall_mmap(call_ctx);
    if(mmap_memory == NULL) {
        return -1;
    }
    // JMP to newly mapped region
    if (singlestep(call_ctx->pid)) {
        goto fail;
    }
    // Verify that JMP got us to the right address
    if (ptrace(PTRACE_GETREGS, call_ctx->pid, NULL, call_ctx->newregs)) {
        perror("PTRACE_GETREGS");
        goto fail;
    }
    if (newregs.rip != (long)mmap_memory) {
        goto fail;
    }
    void * remote_func_addr = call_ctx->remote_libc_addr + (local_function - call_ctx->local_libc_addr);
    
    // memory we are going to copy into our mmap area
    uint8_t new_text[32] = {0};
    // insert a CALL instruction
    size_t offset = 0;
    new_text[offset++] = 0xe8; // CALL rel32
    int32_t fprintf_delta = compute_jmp(mmap_memory, remote_func_addr);
    memmove(new_text + offset, &fprintf_delta, sizeof(fprintf_delta));
    offset += sizeof(fprintf_delta);

    // insert a TRAP instruction
    new_text[offset++] = 0xcc;

    // copy our fprintf format string right after the TRAP instruction
    // I think I can delete this but I want to make sure first
    memmove(new_text + offset, format, strlen(format));

    // update the mmap area
    //printf("inserting code/data into the mmap area at %p\n", mmap_memory);
    if (poke_text(pid, mmap_memory, new_text, NULL, sizeof(new_text))) {
        goto fail;
    }

    if (poke_text(pid, rip, new_word, NULL, sizeof(new_word))) {
        goto fail;
    }

    // Set up registers with the arguments to the target function.
    // For now this a very limitted use case so I am only checking the first six arguments
  
  va_list vl;
  va_start(vl,nargs);
  int i = 0;
  unsigned long long int *regarray[6] = {&newregs.rdi, &newregs.rsi, &newregs.rdx, &newregs.rcx, &newregs.r8, &newregs.r9};
	for( i = 0; i < nargs; ++i ){
	  unsigned long arg = va_arg( vl, long );
		// fill registers with first six arguments		
		memcpy(regarray[i], &arg, sizeof(int));		
	}
	va_end(vl);

/**
  newregs.rax = 0;                          // no vector registers are used
  newregs.rdi = (long)their_stderr;         // pointer to stderr in the caller
  newregs.rsi = (long)mmap_memory + offset; // pointer to the format string
  **/
  

  //printf("setting the registers of the remote process\n");
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // continue the program, and wait for the trap
  //printf("continuing execution\n");
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  if (do_wait("PTRACE_CONT")) {
    goto fail;
  }

  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }
  long ret = newregs.rax;
  newregs.rax = (long)rip;
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  new_word[0] = 0xff; // JMP %rax
  new_word[1] = 0xe0; // JMP %rax
  poke_text(pid, (void *)newregs.rip, new_word, NULL, sizeof(new_word));

  //printf("jumping back to original rip\n");
  if (singlestep(pid)) {
    goto fail;
  }
  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }

  if (newregs.rip == (long)rip) {
    //printf("successfully jumped back to original %%rip at %p\n", rip);
  } else {
    //printf("unexpectedly jumped to %p (expected to be at %p)\n",
    //       (void *)newregs.rip, rip);
    goto fail;
  }
  
  // unmap the memory we allocated
  newregs.rax = SYS_munmap;        // munmap
  newregs.rdi = (long)mmap_memory; // addr
  newregs.rsi = PAGE_SIZE;         // size
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // make the system call
  //printf("making call to mmap\n");
  if (singlestep(pid)) {
    goto fail;
  }
  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }
  //printf("munmap returned with status %llu\n", newregs.rax);

  //printf("restoring old text at %p\n", rip);
  poke_text(pid, rip, old_word, NULL, sizeof(old_word));

  //printf("restoring old registers\n");
  if (ptrace(PTRACE_SETREGS, pid, NULL, &register_save_state)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // detach the process
  //printf("detaching\n");
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
    perror("PTRACE_DETACH");
    goto fail;
  }
  return ret;

fail:
  poke_text(pid, rip, old_word, NULL, sizeof(old_word));
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
    perror("PTRACE_DETACH");
  }
  return 1;
}

