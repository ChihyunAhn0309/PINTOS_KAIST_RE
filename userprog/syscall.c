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
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/palloc.h"

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
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_num = f->R.rax;
	uint64_t arg1 = f->R.rdi;
	uint64_t arg2 = f->R.rsi;
	uint64_t arg3 = f->R.rdx;
	uint64_t arg4 = f->R.r10;
	uint64_t arg5 = f->R.r8;
	uint64_t arg6 = f->R.r9;
	switch(syscall_num){
	case SYS_HALT:{
		power_off();
		break;
	}
	case SYS_EXIT:{
		int status = (int)arg1;
		f->R.rax = status;
		exit_handler(status);
		break;
	}
	case SYS_FORK:{
		const char *thread_name = (const char *)arg1;
		pid_t child_id = fork_handler(thread_name, f);
		f->R.rax = child_id;
		break;
	}
	case SYS_EXEC:{
		const char *cmd_line = (const char *)arg1;
		exec_handler(cmd_line);
		break;
	}
	case SYS_WAIT:{
		pid_t pid = (pid_t)arg1;
		int exit_stat = wait_handler(pid);
		f->R.rax = exit_stat;
		break;
	}
	case SYS_CREATE:{
		const char *file = (const char *)arg1;
		unsigned initial_size = (unsigned)arg2;
		lock_acquire(&filesys_lock);
		bool success = create_handler(arg1, arg2);
		f->R.rax = success;
		lock_release(&filesys_lock);
		break;
	}
	case SYS_REMOVE:{
		const char *file = (const char *)arg1;
		lock_acquire(&filesys_lock);
		bool success = remove_handler(file);
		f->R.rax = success;
		lock_release(&filesys_lock);
		break;
	}
	case SYS_OPEN:{
		const char *file = (const char *)arg1;
		lock_acquire(&filesys_lock);
		int open_fd = open_handler(file);
		f->R.rax = open_fd;
		lock_release(&filesys_lock);
		break;
	}
	case SYS_FILESIZE:{
		int fd = (int)arg1;
		lock_acquire(&filesys_lock);
		int filesize = filesize_handler(fd);
		f->R.rax = filesize;
		lock_release(&filesys_lock);
		break;
	}
	case SYS_READ:{
		lock_acquire(&filesys_lock);
		int fd = (int)arg1;
		void *buffer = (void *)arg2;
		unsigned size = (unsigned)arg3;
		int read_byte = read_handler(fd, buffer, size);
		f->R.rax = read_byte;
		lock_release(&filesys_lock);
		break;
	}
	case SYS_WRITE:{
		lock_acquire(&filesys_lock);
		int fd = (int)arg1;
		const void *buffer = (const void *)arg2;
		unsigned size = (unsigned)arg3;
		int write_byte = write_handler(fd, buffer, size);
		f->R.rax = write_byte;
		lock_release(&filesys_lock);
		break;
	}
	case SYS_SEEK:{
		int fd = (int)arg1;
		unsigned position = (unsigned)arg2;
		lock_acquire(&filesys_lock);
		seek_handler(fd, position);
		lock_release(&filesys_lock);
		break;
	}
	case SYS_TELL:{
		int fd = (int)arg1;
		lock_acquire(&filesys_lock);
		unsigned pos = tell_handler(fd);
		f->R.rax = pos;
		lock_release(&filesys_lock);
		break;
	}
	case SYS_CLOSE:{
		int fd = (int)arg1;
		lock_acquire(&filesys_lock);
		close_handler(fd);
		lock_release(&filesys_lock);
		break;
	}
	default:{
		printf ("system call!\n");
		thread_exit ();
		break;
	}
	}
}

//------------------------------------------------------------------------
//project2: USERPROG

bool is_valid_addr(void* vaddr){
	if(!is_user_vaddr(vaddr) || vaddr == NULL || pml4_get_page(thread_current()->pml4, vaddr) == NULL){
		return false;
	}
	return true;
}
//pml4_get_page 매우 중요!!

bool is_valid_buffer(void* buffer, unsigned length){
	for(int i = 0; i < length; i++){
		if(!is_valid_addr(buffer + i)){
			return false;
		}
	}
	return true;
}

int is_valid_fd(int fd){
	if(fd <= 1 || fd >128){
		return 0;
	}
	if(thread_current()->fd_table[fd] == NULL){
		return 1;
	}
	return 2;
}

void exit_handler (int status){
	struct thread* curr = thread_current();
	curr->exit_stat = status;
	printf ("%s: exit(%d)\n", curr->name, curr->exit_stat);
	// 만약 wait이 존재한다면 sema 사용하기
	// 근데 process_exit에 sema존재 
	// 따라서 sycall handler에서 sema사용이 아닌 thread_exit에서 sema 사용해줘야 할듯.
	thread_exit();
}

pid_t fork_handler (const char *thread_name, struct intr_frame* if_){
	tid_t child_id = process_fork(thread_name, if_);
	if(child_id == -1){
		return -1;
	}
	//thread create에서 메모리 할당 실패한 애들의 경우에는 여기서 return -1
	//그런데 아예 thread자체가 만들어지지 않아서 thread_yield 필요 없다.
	sema_down(&thread_current()->fork_sema);
	struct thread* curr = thread_current();
	if(list_empty(&curr->child_list)){
		return TID_ERROR;
	}
	struct thread* child = NULL;
	for(struct list_elem* iter = list_begin(&curr->child_list); iter != list_end(&curr->child_list); iter = list_next(iter)){
		struct thread* target = list_entry(iter, struct thread, child_elem);
		if(target->tid == child_id){
			child = target;
			// 이 위의 부분 다시 한번 매우 잘 생각하기. 그리고 clean_sema위치도 다시한번 잘 생각해보기.
		}
	}
	if(child == NULL){
		return TID_ERROR;
	}
	if(child->exit_stat == -1){
		list_remove(&child->child_elem);
		sema_up(&child->clean_sema);
		thread_yield();
		return -1;
		// 핀토스 자체는 직접 yield를 하지 않으면 non-preemptive라 절대 CPU 양보하지 않는다.
		// 그래서 우리가 project1에서도 직접 priority들 비교해서 thread_yield해준 것임.
	}
	// fork에서 thread 만들고 intr_frame 복사하는 과정에서 발생하는 메모리 초과의 경우
	// 이미 thread는 만들어졌고 child_elem도 생성 따라서 지워주고 나머지 부분들 전부 정리 필요
	// 따라서 clean_sema를 sema_up해줌. 그 후 해당 자식 정리하라고 thread_yield까지
	return child_id;
	// 각 process가 운용하고 있는 fuction이 필요할듯.
}

int exec_handler (const char *cmd_line){
	if(!is_valid_addr(cmd_line)){
		exit_handler(-1);
	}
	char *fn_copy = palloc_get_page (PAL_ZERO | PAL_USER);
	if (fn_copy == NULL)
		return TID_ERROR;
	memcpy(fn_copy, cmd_line, strlen(cmd_line));
	int success = process_exec(fn_copy);
	if(success == -1){
		exit_handler(-1);
	}
}


int wait_handler (pid_t pid){
	int exit_stat = process_wait(pid);
	return exit_stat;
}

bool create_handler (const char *file, unsigned initial_size){
	if(!is_valid_addr(file)){
		exit_handler(-1);
	}
	bool success = filesys_create(file, initial_size);
	return success;
}

bool remove_handler (const char *file){
	bool success = filesys_remove(file);
	return success;
}

int open_handler (const char *file){
	int next_fd = find_next_fd(thread_current());
	if(is_valid_fd(next_fd) != 1){
		return -1;
	}
	if(!is_valid_addr(file)){
		exit_handler(-1);
	}
	struct file* target = filesys_open(file);
	if(target == NULL){
		return -1;
	}
	thread_current()->fd_table[next_fd] = target;
	return next_fd;
}

int filesize_handler (int fd){
	if(is_valid_fd(fd) != 2){
		exit_handler(-1);
	}
	int size = file_length(thread_current()->fd_table[fd]);
	return size;
}

int read_handler (int fd, void *buffer, unsigned length){
	if(!is_valid_buffer(buffer, length)){
		exit_handler(-1);
		//원래 설명상은 return -1임.
	}
	if(fd == 0){
		char* char_buf = (char*)buffer;
		for(int i = 0; i < length; i++){
			char key = input_getc();
			*(char_buf + i) = key;
		}
		return length;
	}
	if(is_valid_fd(fd) != 2){
		return -1;
		//원래 설명상은 return -1임.
	}
	int read_byte = file_read(thread_current()->fd_table[fd], buffer, length);
	return read_byte;
}

int write_handler (int fd, const void *buffer, unsigned length){
	if(!is_valid_buffer(buffer, length)){
		exit_handler(-1);
		//원래 설명상은 return -1임.
	}
	if(fd == 1){
		putbuf((const char*)buffer, length);
		return length;
	}
	if(is_valid_fd(fd) != 2){
		return -1;
		//원래 설명상은 return -1임.
	}
	int write_byte = file_write(thread_current()->fd_table[fd], buffer, length);
	return write_byte;
}

void seek_handler (int fd, unsigned position){
	if(is_valid_fd(fd) != 2){
		exit_handler(-1);
	}
	struct file* target = thread_current()->fd_table[fd];
	int size = file_length(target);
	if(size < position){
		file_seek(target, size);
	}
	else{
		file_seek(target, position);
	}
	return;
}

unsigned tell_handler (int fd){
	if(is_valid_fd(fd) != 2){
		exit_handler(-1);
	}
	struct file* target = thread_current()->fd_table[fd];
	unsigned pos = file_tell(target);
	return pos;
}

void close_handler (int fd){
	if(is_valid_fd(fd) != 2){
		exit_handler(-1);
	}
	struct file* target = thread_current()->fd_table[fd];
	file_close(target);
	thread_current()->fd_table[fd] = NULL;
	return;
}