#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/interrupt.h"
typedef int pid_t;

void syscall_init (void);


bool is_valid_addr(void* vaddr);
bool is_valid_buffer(void* buffer, unsigned length);
int is_valid_fd(int fd);
void exit_handler (int status);
pid_t fork_handler (const char *thread_name, struct intr_frame* if_);
int exec_handler (const char *file);
int wait_handler (pid_t);
bool create_handler (const char *file, unsigned initial_size);
bool remove_handler (const char *file);
int open_handler (const char *file);
int filesize_handler (int fd);
int read_handler (int fd, void *buffer, unsigned length);
int write_handler (int fd, const void *buffer, unsigned length);
void seek_handler (int fd, unsigned position);
unsigned tell_handler (int fd);
void close_handler (int fd);


#endif /* userprog/syscall.h */
