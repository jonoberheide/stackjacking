
all: stackjack

stackjack: stackjack.o util.o kstack.o leak.o
	gcc stackjack.o util.o kstack.o leak.o -o stackjack

stackjack.o: stackjack.c
	gcc -c stackjack.c

util.o: util.c
	gcc -c util.c

leak.o: leak.c
	gcc -c leak.c

kstack.o: kstack.c kstack.h
	gcc -c kstack.c

clean:
	rm -rf *.o stackjack
