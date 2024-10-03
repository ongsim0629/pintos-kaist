#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");

	char *fn_copy;

	/*
	 x86-64 규약은 함수가 리턴하는 값을 rax 레지스터에 배치하는 것
	 값을 반환하는 시스템 콜은 intr_frame 구조체의 rax 멤버 수정으로 가능
	 */
	switch (f->R.rax) {		// rax is the system call number
		case SYS_HALT:
			halt();			// pintos를 종료시키는 시스템 콜
			break;
		case SYS_EXIT:
			exit(f->R.rdi);	// 현재 프로세스를 종료시키는 시스템 콜
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_EXEC:
			if (exec(f->R.rdi) == -1) {
				exit(-1);
			}
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		default:
			exit(-1);
			break;
	}
	// thread_exit ();
}

void halt(void){
	/* shutdown_power_off()를 사용하여 pintos 종료 */
	shutdown_power_off();
}

void exit (int status)
{
	/* 실행중인 스레드 구조체를 가져옴 */
/* 프로세스 종료 메시지 출력, 
출력 양식: “프로세스이름: exit(종료상태)” */ 
/* 스레드 종료 */
struct thread *cur = thread_current (); 
/* 프로세스 디스크립터에 exit status 저장 */
printf("%s: exit(%d)\n" , cur -> name , status);
thread_exit();
}


bool create(const char *file , unsigned initial_size)
{
/* 파일 이름과 크기에 해당하는 파일 생성 */
/* 파일 생성 성공 시 true 반환, 실패 시 false 반환 */
}


bool remove(const char *file)
{
/* 파일 이름에 해당하는 파일을 제거 */
/* 파일 제거 성공 시 true 반환, 실패 시 false 반환 */
}

int open(const char *file)
{
/* 파일을 open */
/* 해당 파일 객체에 파일 디스크립터 부여 */
/* 파일 디스크립터 리턴 */
/* 해당 파일이 존재하지 않으면 -1 리턴 */
}

int filesize (int fd)
{
/* 파일 디스크립터를 이용하여 파일 객체 검색 */
/* 해당 파일의 길이를 리턴 */
/* 해당 파일이 존재하지 않으면 -1 리턴 */
}

void seek (int fd, unsigned position)
{
/* 파일 디스크립터를 이용하여 파일 객체 검색 */
/* 해당 열린 파일의 위치(offset)를 position만큼 이동 */
}

int read (int fd, void *buffer, unsigned size)
{
/* 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 */
/* 파일 디스크립터를 이용하여 파일 객체 검색 */
/* 파일 디스크립터가 0일 경우 키보드에 입력을 버퍼에 저장 후
버퍼의 저장한 크기를 리턴 (input_getc() 이용) */
/* 파일 디스크립터가 0이 아닐 경우 파일의 데이터를 크기만큼 저
장 후 읽은 바이트 수를 리턴 */
}

unsigned tell (int fd)
{
/* 파일 디스크립터를 이용하여 파일 객체 검색 */
/* 해당 열린 파일의 위치를 반환 */
}

void close (int fd)
{
/* 해당 파일 디스크립터에 해당하는 파일을 닫음 */
/* 파일 디스크립터 엔트리 초기화 */ 
}


int write(int fd, void *buffer, unsigned size)
{
/* 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 */
/* 파일 디스크립터를 이용하여 파일 객체 검색 */
/* 파일 디스크립터가 1일 경우 버퍼에 저장된 값을 화면에 출력
후 버퍼의 크기 리턴 (putbuf() 이용) */
/* 파일 디스크립터가 1이 아닐 경우 버퍼에 저장된 데이터를 크기
만큼 파일에 기록후 기록한 바이트 수를 리턴 */
}

tid_t exec(const char *cmd_line)
{
/* process_execute() 함수를 호출하여 자식 프로세스 생성 */
/* 생성된 자식 프로세스의 프로세스 디스크립터를 검색 */
/* 자식 프로세스의 프로그램이 적재될 때까지 대기 */
/* 프로그램 적재 실패 시 -1 리턴 */
/* 프로그램 적재 성공 시 자식 프로세스의 pid 리턴 */ 
}

int wait(tid_t tid)
{
/* 자식 프로세스가 종료 될 때까지 대기 */
/* process_wait() 사용 */
}

tid_t fork(const char *thread_name, struct intr_frame *f){

}