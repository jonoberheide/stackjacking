unsigned long get_kstack();
unsigned long * leak_bytes();

struct candidate {
        int syscall;
        int index;
        unsigned long kstack;
};

/* A reasonable estimate at the maximum depth from
   the top of the stack a leaked address would reside */
#define DEPTH 500

/* Number of trials to check agreement */
#define NUM_TRIALS 10

/* Threshold for agreement */
#define THRESHOLD 8 

#ifdef __x86_64__
#define KSTACKBASE 0xffff880000000000
#define KSTACKTOP 0xffff8800c0000000
#define MAGIC 0xdeadbeefdeadbeef
#else
#define KSTACKBASE 0xc0000000
#define KSTACKTOP 0xff000000
#define MAGIC 0xdeadbeef
#endif
