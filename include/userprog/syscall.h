#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init(void);

/* Project 2 System Calls */
struct lock filesys_lock;
void close(int fd);

#endif /* userprog/syscall.h */
