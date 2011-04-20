#include <stdlib.h>
#include <stdio.h>

/* Plug in a kernel write exploit primitive here. */
int kernel_write(unsigned long target, unsigned long val)
{

	printf("[*] kernel_write() function has not been filled in.\n");
	exit(-1);

}
