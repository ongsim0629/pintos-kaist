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
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* Function prototypes for all system calls */
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
void seek(int fd, unsigned position);
int read(int fd, void *buffer, unsigned size);
unsigned tell(int fd);  // Returns unsigned
void close(int fd);
int write(int fd, void *buffer, unsigned size);
tid_t exec(const char *cmd_line);
int wait(tid_t tid);
tid_t fork(const char *thread_name, struct intr_frame *f);
void check_address(void *addr);

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
struct lock filesys_lock;

void
syscall_init (void) {
	lock_init(&filesys_lock);

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
    // 유효한 시스템 콜인지 확인
    switch (f->R.rax) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_CREATE:
            check_address((void *)f->R.rdi);  // 파일 이름 포인터의 유효성 검사
            f->R.rax = create((const char *)f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            check_address((void *)f->R.rdi);  // 파일 이름 포인터의 유효성 검사
            f->R.rax = remove((const char *)f->R.rdi);
            break;
        case SYS_OPEN:
            check_address((void *)f->R.rdi);  // 파일 이름 포인터의 유효성 검사
            f->R.rax = open((const char *)f->R.rdi);
            break;
        case SYS_READ:
            check_address((void *)f->R.rsi);  // 버퍼 포인터의 유효성 검사
            f->R.rax = read(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            check_address((void *)f->R.rsi);  // 버퍼 포인터의 유효성 검사
            f->R.rax = write(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
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
        default:
            exit(-1);
            break;
    }
}

// 사용자 프로그램이 커널에 요청을 할 때 전달하는 포인터 인자들의 검증과정에서 사용되는 함수, 만약에 포인터가 유효하지 않으면 사용자프로그램이 종료된다.
void check_address(void *addr) {
    // 포인터가 NULL이거나 커널 영역이거나, 페이지가 없으면 프로세스를 종료
    if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL) {
        exit(-1);  // 비정상적인 메모리 접근 시 종료
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
	check_address(file);
	/* 파일 이름과 크기에 해당하는 파일 생성 */
	/* 파일 생성 성공 시 true 반환, 실패 시 false 반환 */
	return filesys_create(file, initial_size);
}


bool remove(const char *file)
{
	check_address(file);
	/* 파일 이름에 해당하는 파일을 제거 */
	return filesys_remove(file);
	/* 파일 제거 성공 시 true 반환, 실패 시 false 반환 */
	// remove 플래그 등의 처리는 기존의 함수에서 이루어짐
}

int open(const char *file)
{
	check_address(file);
	/* 파일을 open */
	struct file* curr_file = filesys_open(file);
	
	if (curr_file == NULL) {
        return -1;  // 파일이 존재하지 않으면 -1 반환
    }

	/* 해당 파일 객체에 파일 디스크립터 부여 */
	int fd = process_add_file(curr_file);

	/* 파일 디스크립터 리턴 */
	return fd;
}

int filesize (int fd)
{
	 if (fd < 0 || fd >= 64) {
        return -1;
    }

	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *curr_file = process_get_file(fd);

	/* 해당 파일이 존재하지 않으면 -1 리턴 */
	if (curr_file == NULL){
		return -1;
	}
	
	/* 해당 파일의 길이를 리턴 */
	return file_length(curr_file);
}

// 열린 파일의 위치(offset)를 이동하는 시스템 콜
void seek (int fd, unsigned position)
{
	if (fd < 0 || fd >= 64) {
        return;
	}

	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *curr_file = process_get_file(fd);

	if (curr_file == NULL){
		return;
	}

    /* 해당 열린 파일의 위치(offset)를 position으로 이동 */
    file_seek(curr_file, position);
}

int read(int fd, void *buffer, unsigned size)
{
    /* 읽은 데이터를 저장할 버퍼의 주소 값 저장 */
    check_address(buffer);  // 버퍼 주소가 유효한지 확인

    int result = -1;

    /* 파일 디스크립터가 0일 경우: 키보드 입력 처리 */
	// 최대 size만큼 읽지만, 실제로 입력된 글자의 수만큼만 반환
    if (fd == 0) {
		int i;
		unsigned char *buf = buffer;

		for (i = 0; i < size; i++) {
			char c = input_getc();
			*buf++ = c;
			if (c == '\0') {
				break;
			}
		}
		result = i;
    }

    /* 파일 디스크립터가 1일 경우: 읽기 불가능하므로 에러 반환 */
    if (fd == 1) {
        return -1;
    }

    /* 파일 디스크립터를 이용하여 파일 객체 검색 */
    struct file *curr_file = process_get_file(fd);
    if (curr_file == NULL) {
        return -1;  // 파일 객체가 없을 때 에러 반환
    }

    /* 파일 데이터를 읽고, 읽은 바이트 수 반환 */
    lock_acquire(&filesys_lock);  // 파일 접근 중 동시성 문제를 방지하기 위한 락 사용
    result = file_read(curr_file, buffer, size);  // 파일에서 읽은 바이트 수
    lock_release(&filesys_lock);

    return result;
}

unsigned tell (int fd)
{
	if (fd < 0 || fd >= 64) {
		// unsigned인데 어떻게 처리할 지 좀 더 생각해보기
        // return -1;
		return (unsigned)-1;
	}

	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *curr_file = process_get_file(fd);

	if (curr_file == NULL){
		// return -1;
		return (unsigned)-1;
	}
	
	/* 해당 열린 파일의 위치를 반환 */
	return file_tell(curr_file);
}

void close (int fd)
{
	if (fd < 0 || fd >= 64) {
		return;
	}

	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *curr_file = process_get_file(fd);

	if (curr_file == NULL){
		return;
	}

    /* 파일 디스크립터 엔트리 초기화 */
    process_close_file(fd);
}


int write(int fd, void *buffer, unsigned size)
{
    /* 버퍼 주소가 유효한지 확인 */
    check_address(buffer);

    int result = -1;

    /* 표준 출력(stdout) 처리: fd == 1 */
    if (fd == 1) {
        putbuf(buffer, size);  // 버퍼의 데이터를 출력
        return size;  // 출력된 바이트 수 반환
    }

    /* 표준 입력(stdin)인 fd == 0에서는 쓰기 작업이 불가능하므로 에러 반환 */
    if (fd == 0) {
        return -1;
    }

    /* 파일 디스크립터를 이용하여 파일 객체 검색 */
    struct file *curr_file = process_get_file(fd);
    if (curr_file == NULL) {
        return -1;  // 파일 객체가 없으면 에러 반환
    }

    /* 파일에 데이터를 쓰는 작업 */
    lock_acquire(&filesys_lock);  // 파일 접근 중 동시성 문제를 방지하기 위한 락 사용
    result = file_write(curr_file, buffer, size);  // 파일에 데이터를 쓰고 쓴 바이트 수 반환
    lock_release(&filesys_lock);

    return result;  // 실제로 쓴 바이트 수 반환
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