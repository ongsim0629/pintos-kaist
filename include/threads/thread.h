#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "synch.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */


/* FDT에 저장할 수 있는 파일 디스크립터의 최대 개수 */
#define FDT_COUNT_LIMIT 64

/*fdt의 총 크기와 필요한 페이지 수 계산 */
#define FDT_SIZE (sizeof(struct file *) * 64) // file 64개
#define FDT_PAGES ((FDT_SIZE + PGSIZE - 1) / PGSIZE)


struct thread *get_idle_thread(void);

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */

struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	int64_t local_ticks; 				/* local ticks */
	int original_priority;

	struct lock *wait_on_lock;
	struct list donations;
	struct list_elem d_elem; 
	
	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

	/* for MLFQ */
	int nice;
	int recent_cpu;

	/* [Project 2] for file system*/
	struct file **fd_table;
	int next_fd;

	/* [Project 2] for process hierarchy */
	//bool create_succ; // 프로세스의 생성 성공 여부 (실패 시 -1 )
	//bool is_exited; // 프로세스의 종료 유무

	int load_status; // 프로세스의 생성 상태 (프로세스가 완전히 생성되었는지)
	int exit_status; // 프로세스의 종료 상태

	struct semaphore fork_sema; // 자식 프로세스의 생성 대기를 위한 세마포어
	struct semaphore exit_sema; // 자식 프로세스의 종료 대기를 위한 세마포어

	struct list child_list; // 자식 프로세스 리스트 필드
	struct list_elem child_elem; // 부모 프로세스에 현재 스레드를 자식으로 추가하기 위한 필드

	struct intr_frame parent_if; // 부모 프로세스 인터럽트 프레임

	/* [Project 2] for file system*/
	struct file **fd_table;
	int next_fd;
	
#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

bool list_higher_priority (const struct list_elem *a, const struct list_elem *b, void *aux);

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
extern struct list ready_list;
extern struct list sleep_list;
extern struct list blocked_list;

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

void thread_sleep (int64_t ticks);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);


/* for MLFQ */
#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0
extern int load_avg;

void mlfqs_priority (struct thread *t); 
void mlfqs_recent_cpu (struct thread *t); // 각 스레드가 최근에 사용한 CPU 시간
void mlfqs_load_avg (void); // ready_list에 대기 중인 스레드의 개수
void mlfqs_increment (void);
void mlfqs_recalc (void);

#endif /* threads/thread.h */