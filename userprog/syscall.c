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
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* Project 2 System Calls */
void halt(void);
void exit(int status);
int exec(const char *cmd_line);
tid_t fork(const char *thread_name, struct intr_frame *f);

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
    // f->R.rax = process_wait(f->R.rdi);
    break;
  case SYS_CREATE:
    // f->R.rax = create(f->R.rdi, f->R.rsi);
    break;
  case SYS_REMOVE:
    // f->R.rax = remove(f->R.rdi);
    break;
  case SYS_OPEN:
    // f->R.rax = open(f->R.rdi);
    break;
  case SYS_FILESIZE:
    // f->R.rax = filesize(f->R.rdi);
    break;
  case SYS_READ:
    // f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
    break;
  case SYS_WRITE:
    break;
  case SYS_SEEK:
    break;
  case SYS_TELL:
    break;
  case SYS_CLOSE:
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
int exec(const char *cmd_line) {
  // 유저 프로그램으로부터 포인터를 받는 것이기 때문에 check를 할 필요가 있다.
  check_address(cmd_line);

  char *cmd_line_copy;
  cmd_line_copy = palloc_get_page(0);
  if (cmd_line_copy == NULL)
    exit(-1);
  strlcpy(cmd_line_copy, cmd_line, PGSIZE);

  if (process_exec(cmd_line_copy) == -1)
    exit(-1);
}

tid_t fork(const char *thread_name, struct intr_frame *f) {

  return process_fork(thread_name, f);
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
