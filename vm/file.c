/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	struct load_arg* aux = (struct load_arg*)malloc(sizeof(struct load_arg));
	memcpy(aux, page->uninit.aux, sizeof(struct load_arg));
	memset(&page->uninit, 0, sizeof(struct uninit_page));
	file_page->file = aux->file;
	file_page->read_bytes = aux->read_bytes;
	file_page->zero_bytes = aux->zero_bytes;
	file_page->offs = aux->offs;
	// lazy_load_segment에서 할당해주면 통과.
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	off_t read_bytes = file_read_at (file_page->file, page->frame->kva, file_page->read_bytes, file_page->offs);
	if(read_bytes != file_page->read_bytes){
		return false;
	}
	memset(page->frame->kva + file_page->read_bytes, 0, file_page->zero_bytes);
	pml4_set_page(thread_current()->pml4, page->va, kva, page->rw);
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	if(pml4_is_dirty(thread_current()->pml4, page->va)){
		file_write_at(file_page->file, page->frame->kva, file_page->read_bytes, file_page->offs);
		//page->frame->kva여야 한다. 왜냐하면 page->va는 pml4를 통해서 실제 데이터와 연결
		//따라서 이 코드를 실행하는 것은 kernel 따라서 kernel이 실제 데이터에 접근하려면 page->frame->kva를 사용
		pml4_set_dirty(thread_current()->pml4, page->va, false);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
	//pml4에서 제거하는거 중요
	page->frame->page = NULL;
	page->frame = NULL;
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	if(page->frame != NULL){
		if(pml4_is_dirty(thread_current()->pml4, page->va)){
			file_write_at(page->file.file, page->frame->kva, page->file.read_bytes, page->file.offs);
			//file_page로 수정하기
			pml4_set_dirty(thread_current()->pml4, page->va, false);
		}
		list_remove(&page->frame->frame_elem);
		page->frame->page = NULL;
		free(page->frame);
		page->frame = NULL;
		//pml4_destroy함수에서 해당 frame palloc_free_page해준다.
	}
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	lock_acquire(&filesys_lock);
	struct file* re_file = file_reopen(file);
	size_t file_size = file_length(re_file);
	void* target = addr;
	if(file_size <= offset){
		goto err;
	}
	if(length > file_size - offset){
		length = file_size - offset;
	}
	if(addr == NULL){
		void* vaddr = 0;
		while(is_user_vaddr(vaddr)){
			int flag = 1;
			off_t offs = 0;
			if(!is_user_vaddr(vaddr + length)){
				break;
			}
			while(offs < length){
				if(pml4_get_page(thread_current()->pml4, vaddr + offs) != NULL){
					flag = 0;
					break;
				}
				offs += PGSIZE;
			}
			if(flag == 1){
				target = vaddr;
				break;
			}
			vaddr += PGSIZE;
		}
		if(target == NULL){
			goto err;
		}
	// 이거는 따로 구현하지 않아도 되는 것 같음. 이게 잘 작동하는지도 모르겠음.
	}
	void* ret_addr = target;
	size_t read_bytes = length;
	off_t offs = offset;
	while(read_bytes > 0){
		size_t page_read_bytes = (read_bytes > PGSIZE ? PGSIZE : read_bytes);
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		struct load_arg* aux = (struct load_arg*)malloc(sizeof(struct load_arg));
		aux->file = re_file;
		aux->read_bytes = page_read_bytes;
		aux->zero_bytes = page_zero_bytes;
		aux->offs = offs;
		if(!vm_alloc_page_with_initializer(VM_FILE, target, writable, lazy_load_segment, (void*)aux)){
			free(aux);
			goto err;
		}
		
		/* Advance. */
		read_bytes -= page_read_bytes;
		offs += page_read_bytes;
		target += PGSIZE;
	}
	lock_release(&filesys_lock);
	return ret_addr;

err:
	file_close(re_file);
	lock_release(&filesys_lock);
	return NULL;

}


/* Do the munmap */
void
do_munmap (void *addr) {
	if(addr == NULL || !is_user_vaddr(addr)){
		return;
	}
	lock_acquire(&filesys_lock);
	struct page* target = spt_find_page(&thread_current()->spt, addr);
	struct file* target_file = NULL;
	while(target != NULL){
		if(page_get_type(target) != VM_FILE){
			break;
		}
		target_file = target->file.file;
		destroy(target);
		addr = addr + PGSIZE;
		target = spt_find_page(&thread_current()->spt, addr);
	}
	if(target_file != NULL){
		file_close(target_file);
	}
	lock_release(&filesys_lock);
}
