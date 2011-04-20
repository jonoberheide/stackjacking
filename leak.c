#include <stdio.h>
#include <stdlib.h>

#include "kstack.h"

/* Include any setup code needed for the leak here.
 *
 * Returns 0 on success, -1 on failure.
 */
int setup()
{

	return 0;

}

/* Leverage a leak of uninitialized structure members
 * off the kernel stack.  Allocate an array of longs
 * and fill it with the leaked bytes, terminating with
 * the MAGIC value.
 *
 * Returns a pointer to the leak array.
 */
unsigned long * leak_bytes()
{

	printf("[*] leak_bytes() function has not been filled in.\n");
	exit(-1);

}
