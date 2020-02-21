#include "tracer.h"

void *findFunction( const char* library, void* local_addr ){
	long local_handle;
	long remote_handle;
	local_handle = findLibrary( library, getpid() );
	remote_handle = findLibrary( library, -1 );
	return local_addr + remote_handle - local_handle;
}

long findLibrary( const char *library, pid_t pid) {
	char filename[0xFF] = {0},
			buffer[1024] = {0};
	FILE *fp = NULL;
	long address = 0;
	sprintf( filename, "/proc/%d/maps", pid == -1 ? _pid : pid );

	fp = fopen( filename, "rt" );
	if( fp == NULL ){
		perror("fopen");
		goto done;
	}
	while( fgets( buffer, sizeof(buffer), fp ) ) {
		if( strstr( buffer, library ) ){
			address = strtoul( buffer, NULL, 16 );
			goto done;
		}
	}
	done:
	if(fp){
		fclose(fp);
	}
	return address;
}

long trace( int request, void *addr, size_t data) {
	long ret = ptrace( request, _pid, addr, (void *)data );
	if( ret == -1 && (errno == EBUSY || errno == EFAULT || errno == ESRCH) ){
		perror("ptrace");
		return -1;
	}
	return ret;
}

// Remotely force the target process to dlopen a library.
unsigned long myDlopen( const char *libname ) {
	unsigned long pmem = copyString(libname);
	unsigned long plib = call( _dlopen, 2, pmem, 0 );

	myFree(pmem);

	return plib;
}

// Remotely call dlsym on the target process.
unsigned long myDlsym( unsigned long dl, const char *symname ) {
	unsigned long pmem = copyString(symname);
	unsigned long psym = call( _dlsym, 2, dl, pmem );

	myFree(pmem);

	return psym;
}

// Free remotely allocated memory.
void myFree( unsigned long p ) {
	call( _free, 1, p );
}

unsigned long copyString( const char *s ) {
	unsigned long mem = call( _calloc, 2, strlen(s) + 1, 1 );
	write( mem, (unsigned char *)s, strlen(s) + 1 );
	return mem;
}

void start_trace(pid_t pid) {
	if( trace( PTRACE_ATTACH, 0, 0) != -1 ){
		int status;
		waitpid( _pid, &status, 0 );

		/*
			* First thing first, we need to search these functions into the target
			* process address space.
			*/
		_dlopen  = findFunction( "/system/bin/linker", (void *) myDlopen );
		_dlsym   = findFunction( "/system/bin/linker", (void *) myDlsym );
		_dlerror = findFunction( "/system/bin/linker", (void *) dlerror );
		_calloc  = findFunction( "/system/lib/libc.so", (void *) calloc );
		_free    = findFunction( "/system/lib/libc.so", (void *) free );

		if( !_calloc ){
			fprintf( stderr, "Could not find calloc symbol.\n" );
		}
		else if( !_free ){
			fprintf( stderr, "Could not find dlopen symbol.\n" );
		}
		else if( !_dlopen ){
			fprintf( stderr, "Could not find dlopen symbol.\n" );
		}
		else if( !_dlsym ){
			fprintf( stderr, "Could not find dlsym symbol.\n" );
		}
		else if( !_dlerror ){
			fprintf( stderr, "Could not find dlerror symbol.\n" );
		}
	}
	else {
		fprintf( stderr, "Failed to attach to process %d.", _pid );
	}
}

    unsigned long call( void *function, int nargs, ... ) {
        int i = 0;
        struct pt_regs regs = {{0}}, rbackup = {{0}};

        // get registers and backup them
        trace( PTRACE_GETREGS, 0, (size_t)&regs );
        memcpy( &rbackup, &regs, sizeof(struct pt_regs) );

        va_list vl;
        va_start(vl,nargs);

        for( i = 0; i < nargs; ++i ){
            unsigned long arg = va_arg( vl, long );

            // fill R0-R3 with the first 4 arguments
            if( i < 4 ){
                regs.uregs[i] = arg;
            }
            // push remaining params onto stack
            else {
                regs.ARM_sp -= sizeof(long) ;
                write( (size_t)regs.ARM_sp, (uint8_t *)&arg, sizeof(long) );
            }
        }

        va_end(vl);

        regs.ARM_lr = 0;
        regs.ARM_pc = (long int)function;
        // setup the current processor status register
        if ( regs.ARM_pc & 1 ){
            /* thumb */
            regs.ARM_pc   &= (~1u);
            regs.ARM_cpsr |= CPSR_T_MASK;
        }
        else{
            /* arm */
            regs.ARM_cpsr &= ~CPSR_T_MASK;
        }

        // do the call
        trace( PTRACE_SETREGS, 0, (size_t)&regs );
        trace( PTRACE_CONT, 0,0);
        waitpid( _pid, NULL, WUNTRACED );

        // get registers again, R0 holds the return value
        trace( PTRACE_GETREGS, 0, (size_t)&regs );

        // restore original registers state
        trace( PTRACE_SETREGS, 0, (size_t)&rbackup );

        return regs.ARM_r0;
    }
