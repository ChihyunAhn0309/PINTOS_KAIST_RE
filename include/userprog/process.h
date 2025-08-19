#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

//----------------------------------------------------------------
//project2: USERPROG
void argument_passing(int argc, char** argv, struct intr_frame *if_);
int find_next_fd(struct thread* target);

struct fork_arg{
    struct intr_frame* if_;
    struct thread* parent;
};

#endif /* userprog/process.h */
