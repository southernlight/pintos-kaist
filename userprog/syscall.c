#include "userprog/syscall.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include <stdio.h>
#include <syscall-nr.h>

/* Project 2 System Calls */
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* Project 2 User Mermory Access */
void check_address(void *addr);

/* Project 2 System Calls */
void halt(void);                                           // O
void exit(int status);                                     // O
tid_t fork(const char *thread_name, struct intr_frame *f); // O
int exec(const char *cmd_line);                            // O
int wait(tid_t pid);                                       // O
bool create(const char *file, off_t initial_size);         // O
bool remove(const char *file);                             // O
int open(const char *file);                                // O
int filesize(int fd);                                      // O
int read(int fd, void *buffer, unsigned size);             // O
int write(int fd, const void *buffer, unsigned size);      // O
void seek(int fd, unsigned position);                      // O
unsigned tell(int fd);                                     // O
void close(int fd);                                        // O

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

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
  lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
  // TODO: Your implementation goes here.
  // printf("system call!\n");

  /* Project 2 System Calls*/
  int syscall_num = f->R.rax;
  switch (syscall_num) {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    exit(f->R.rdi);
    break;
  case SYS_FORK:
    f->R.rax = fork(f->R.rdi, f);
    break;
  case SYS_EXEC:
    f->R.rax = exec(f->R.rdi);
    break;
  case SYS_WAIT:
    f->R.rax = wait(f->R.rdi);
    break;

  /* 아래부터는 File System 부분 시스템 콜 */
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
  case SYS_WRITE:
    f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
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
  // thread_exit();
}

/* Project 2 System Calls */
void halt(void) { power_off(); }

void exit(int status) {
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

tid_t fork(const char *thread_name, struct intr_frame *f) {

  return process_fork(thread_name, f);
}

int exec(const char *cmd_line) {
  // 유저 프로그램으로부터 포인터를 받는 것이기 때문에 check를 할 필요가 있다.
  check_address(cmd_line);

  char *cmd_line_copy;
  cmd_line_copy = palloc_get_page(0);
  if (cmd_line_copy == NULL) {
    exit(-1);
  }
  strlcpy(cmd_line_copy, cmd_line, PGSIZE);

  if (process_exec(cmd_line_copy) == -1) {
    exit(-1);
  }
}

int wait(tid_t pid) { return process_wait(pid); }

// File system 관련 함수
bool create(const char *file, off_t initial_size) {
  check_address(file);
  return filesys_create(file, initial_size);
}

bool remove(const char *file) {
  check_address(file);
  return filesys_remove(file);
}

int open(const char *file_name) {
  check_address(file_name);
  lock_acquire(&filesys_lock);
  struct file *file = filesys_open(file_name);
  if (file == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  int fd = process_add_file(file);
  if (fd == -1)
    file_close(file);
  lock_release(&filesys_lock);
  return fd;
}

int filesize(int fd) {
  struct file *open_file = process_get_file(fd);
  if (open_file == NULL)
    return -1;
  return file_length(open_file);
}

int read(int fd, void *buffer, unsigned size) {
  check_address(buffer);

  char *buf = (char *)buffer;
  int bytes = 0;
  lock_acquire(&filesys_lock);

  if (fd == 0) {
    for (int i = 0; i < size; i++) {
      buf[i] = input_getc();
      bytes++;
    }
    lock_release(&filesys_lock);
  } else if (fd < 2) {
    lock_release(&filesys_lock);
    return -1;
  } else {
    struct file *file = process_get_file(fd);
    if (file == NULL) {
      lock_release(&filesys_lock);
      return -1;
    }
    bytes = file_read(file, buf, size);
    lock_release(&filesys_lock);
  }

  return bytes;
}

int write(int fd, const void *buffer, unsigned size) {
  check_address(buffer);
  int bytes = 0;

  if (fd == 1) {
    putbuf(buffer, size);
    bytes = size;
  } else if (fd < 2) {
    return -1;
  } else {
    struct file *file = process_get_file(fd);
    if (file == NULL) {
      return -1;
    }
    lock_acquire(&filesys_lock);
    bytes = file_write(file, buffer, size);
    lock_release(&filesys_lock);
    return bytes;
  }
}

void seek(int fd, unsigned position) {
  struct file *file = process_get_file(fd);
  if (file == NULL)
    return;
  file_seek(file, position);
}

unsigned tell(int fd) {
  struct file *file = process_get_file(fd);
  if (file == NULL)
    return;
  return file_tell(file);
}

void close(int fd) {
  struct file *file = process_get_file(fd);
  if (file == NULL)
    return;
  file_close(file);
  // 파일 디스크립터 테이블에서 파일 객체를 제거하는 함수
  process_close_file(fd);
}

/* Project 2 User Memory Access*/
void check_address(void *addr) {
  if (addr == NULL)
    exit(-1);
  if (!is_user_vaddr(addr))
    exit(-1);
  /*유저 프로세스의 페이지 테이블에서 주어진 주소가 실제로 물리적 메모리에
   매핑되어 있는지 확인*/
  if (pml4_get_page(thread_current()->pml4, addr) == NULL)
    exit(-1);
}
