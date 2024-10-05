#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>
#include "threads/thread.h"
void syscall_init (void);
void check_address(void *addr);

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
#endif /* userprog/syscall.h */
