#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"

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

void check_address(void *addr);

void syscall_handler (struct intr_frame *f);
/* 시스템 종료 */
void halt(void);

/* 프로세스 종료 */
void exit(int status);

/* 파일 생성 */
bool create(const char *file, unsigned initial_size);

/* 파일 제거 */
bool remove(const char *file);

/* 파일 열기 */
int open(const char *file);

/* 파일 크기 반환 */
int filesize(int fd);

/* 파일의 위치 이동 */
void seek(int fd, unsigned position);

/* 파일 또는 키보드로부터 읽기 */
int read(int fd, void *buffer, unsigned size);

/* 파일 위치 반환 */
unsigned int tell(int fd);

/* 파일 닫기 */
void close(int fd);

/* 파일 또는 화면에 쓰기 */
int write(int fd, void *buffer, unsigned size);

/* 새로운 프로그램 실행 */
tid_t exec(const char *cmd_line);

/* 자식 프로세스가 종료될 때까지 대기 */
int wait(tid_t tid);

/* 프로세스를 복제하여 자식 프로세스 생성 */
tid_t fork(const char *thread_name, struct intr_frame *f);


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

// 사용자 프로그램이 커널에 요청을 할 때 전달하는 포인터 인자들의 검증과정에서 사용되는 함수, 만약에 포인터가 유효하지 않으면 사용자프로그램이 종료된다.
void check_address(void *addr){
    // 유효하지 않은 영역 : null pointer, 커널 메모리 공간 가리키는 포인터, 페이지 테이블에 매핑되지 않은 메모리를 참조하는 지 확인
    // 유효하지 않은 영역 가리키는 포인터일 때 -> 프로세스 종료 exit() : 자원의 해제 이루어져야함
    if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr)== NULL){
        // 비정상적 종료이므로 인자 -1
        exit(-1);
    }
}

/* 유저 스택에 저장된 인자값들을 커널에 저장 */
/* 인자가 저장된 위치가 유저 영역인지 확인 */
// x86-64 아키텍처에서는 get_argument() 함수 없이도 시스템 콜 인자를 레지스터를 통해 커널 영역으로 바로 전달할 수 있음
// void get_argument(void *esp, int *arg, int count) {

// 	// esp: 스택에서 시스템 콜 번호가 저장된 위치
// 	// 실제 인자들은 그 다음 위치부터 저장됨
// 	void *addr;
// 	for (int i = 0; i < count; i++) {
// 		addr = esp + 4 * (i + 1);	
// 		check_address(addr);	// addr가 유효한 유저 영역 주소값인지 검증 
// 		arg[i] = * (int *)addr; 	// addr가 가리키는 영역의 값을 arg에 저장
// 	}

	
// 	// arg에 담긴 값이 포인터라면, 그 역시도 유효한 유저영역 주소인지 검증해줘야 한다. 
// 	// check_address(arg[i]) -> <함수 밖에서> 인자 사용할 때 처리
// }

void halt(void){
	/* shutdown_power_off()를 사용하여 pintos 종료 */
	power_off();
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

unsigned int tell (int fd)
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

// process_exec 함수를 이용해서 인자로 받은 cmd_line을 실 
tid_t exec(const char *cmd_line)
{
	// 1. cmd_line 주소 검증
	check_address(cmd_line);

	// 2. process_exec에 전달할 cmd_line 복사본 만들기
	char *cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		exit(-1);
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	// 3. process_exec 함수 호출
	if (process_exec(cmd_line_copy) == -1) {
		palloc_free_page(cmd_line_copy); // 실패했을 경우 메모리 해제
		exit(-1);
	}
}

int wait(tid_t tid)
{
/* 자식 프로세스가 종료 될 때까지 대기 */
/* process_wait() 사용 */
}

// 현재 프로세스를 복제하여 새로운 자식 프로세스를 생성
tid_t fork(const char *thread_name, struct intr_frame *f){
	/* process_execute() 함수를 호출하여 자식 프로세스 생성 */ 
	/* 생성된 자식 프로세스의 프로세스 디스크립터를 검색 */
	/* 자식 프로세스의 프로그램이 적재될 때까지 대기  -> sema_down() */
	/* 프로그램 적재 실패 시 -1 리턴 */
	/* 프로그램 적재 성공 시 자식 프로세스의 pid 리턴 */ 

	/*
	1. 자식 프로세스 생성 - process_fork()
	2. 부모 프로세스 상태 복사 - intr_frame 이용
	3. 자식 프로세스 실행 -> 로드 완료할 때 까지 부모 프로세스는 대기 - sema 
	4. 프로세스 생성 성공 여부 반환 - thread->load_status
	*/
	return process_fork(thread_name, f);
}