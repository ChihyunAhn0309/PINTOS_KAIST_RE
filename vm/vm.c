/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "hash.h"
#include "threads/mmu.h"
#include "userprog/process.h"
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page* new_page = (struct page*)malloc(sizeof(struct page));
		if(new_page == NULL){
			return false;
		}
		if(VM_TYPE(type) == VM_ANON){
			uninit_new(new_page, upage, init, type, aux, anon_initializer);
		}
		else if(VM_TYPE(type) == VM_FILE){
			uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
		}
		new_page->rw = writable;
		new_page->owner = thread_current();
		/* TODO: Insert the page into the spt. */
		bool succ = spt_insert_page(spt, new_page);
		if(succ == false){
			free(new_page);
		}
		return succ;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = (struct page*)malloc(sizeof(struct page));
	page->va = pg_round_down(va);
	struct hash_elem* target = hash_find(&spt->spt_hash, &page->hash_elem);
	free(page);
	if(target == NULL){
		return NULL;
	}
	struct page* ret_page = hash_entry(target, struct page, hash_elem);
	return ret_page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	struct hash_elem* old = hash_insert(&spt->spt_hash, &page->hash_elem);
	if(old == NULL){
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	if(list_empty(&frame_table)){
		return NULL;
	}
	//struct list_elem* iter;
	//for(iter = list_next(iter_pos); iter != list_end(&frame_table); iter = list_next(iter)){
	//	struct frame* target = list_entry(iter, struct frame, frame_elem);
	//	if(pml4_is_accessed(thread_current()->pml4, target->page->va)){
	//		pml4_set_accessed(thread_current()->pml4, target->page->va, false);
	//	}
	//	else{
	//		victim = target;
	//		iter_pos = list_prev(iter);
	//		break;
	//	}
	//}
	//if(victim != NULL){
	//	return victim;
	//}
	struct list_elem* iter;
	for(iter = list_begin(&frame_table); iter != list_end(&frame_table); iter = list_next(iter)){
		struct frame* target = list_entry(iter, struct frame, frame_elem);
		if(pml4_is_accessed(thread_current()->pml4, target->page->va)){
			pml4_set_accessed(thread_current()->pml4, target->page->va, false);
		}
		else{
			if(target->page->owner == thread_current()){
				victim = target;
				break;
			}
			continue;
		}
	}
	if(victim == NULL){
		for(iter = list_begin(&frame_table); iter != list_end(&frame_table); iter = list_next(iter)){
			struct frame* target = list_entry(iter, struct frame, frame_elem);
			if(pml4_is_accessed(thread_current()->pml4, target->page->va)){
				pml4_set_accessed(thread_current()->pml4, target->page->va, false);
			}
			else{
				if(target->page->owner == thread_current()){
					victim = target;
					break;
				}
				continue;
			}
		}
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	list_remove(&victim->frame_elem);
	bool succ = swap_out(victim->page);
	if(!succ){
		return NULL;
	}
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	void* kva = palloc_get_page(PAL_ZERO | PAL_USER);
	if(kva == NULL){
		frame = vm_evict_frame();
		ASSERT(frame->kva != NULL);
	}
	else{
		frame = (struct frame*)malloc(sizeof(struct frame));
		frame->kva = kva;
	}
	list_push_back(&frame_table, &frame->frame_elem);
	frame->page = NULL;
	//frame setting하기
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	void* target_addr = pg_round_down(addr);
	bool succ;
	succ = vm_alloc_page(VM_STACK | VM_ANON, target_addr, true);
	if(succ == false){
		return;
	}
	succ = vm_claim_page(target_addr);
	if(succ == false){
		return;
	}
	thread_current()->stack_bottom -= PGSIZE;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	return false;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if(!is_user_vaddr(addr)){
		return false;
	}
	if(addr == NULL){
		return false;
	}
	if(not_present){
		uintptr_t user_rsp;
		if(user){
			user_rsp = f->rsp;
		}
		else{
			user_rsp = thread_current()->user_rsp;
		}
		if(USER_STACK >=addr && addr >= user_rsp - 8){
			if(USER_STACK - (int)addr > (1<<20)){
				return false;
			}
			if(USER_STACK - thread_current()->stack_bottom < (1<<20)){
				vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
				return true;
			}
			//만약 stack 할당이 초과되면 stack말고 일반 page로 할당시킨다.
			//아마 stack 바로 밑 페이지에서 page_fault 나는것 같기도 함?
		}
		page = spt_find_page(spt, addr);
		if(page == NULL){
			return false;
		}
		bool succ = vm_do_claim_page (page);
		return succ;
	}
	else{
		page = spt_find_page(spt, addr);
		if(page == NULL){
			return false;
		}
		if(write && !page->rw){
			return vm_handle_wp(page);
		}
	}
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	if(page == NULL){
		return false;
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	bool succ = pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->rw);
	if(succ){
		succ = swap_in (page, frame->kva);
		return succ;
	}
	return succ;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	ASSERT(spt != NULL);
	bool succ = hash_init(&spt->spt_hash, spt_hash_func, spt_hash_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator iter;
	hash_first(&iter, &src->spt_hash);
	bool succ;
	while(hash_next(&iter)){
		struct page* parent_page = hash_entry(iter.elem, struct page, hash_elem);
		enum vm_type parent_type = parent_page->operations->type;
		if(parent_type == VM_UNINIT){
			struct load_arg* child_aux = (struct load_arg*)malloc(sizeof(struct load_arg));
			memcpy(child_aux, parent_page->uninit.aux, sizeof(struct load_arg));
			succ = vm_alloc_page_with_initializer(page_get_type(parent_page), parent_page->va, parent_page->rw, 
			parent_page->uninit.init, (void*)child_aux);
		}
		else if(parent_type == VM_FILE){
			struct load_arg* child_aux = (struct load_arg*)malloc(sizeof(struct load_arg));
			child_aux->file = parent_page->file.file;
			child_aux->read_bytes = parent_page->file.read_bytes;
			child_aux->zero_bytes = parent_page->file.zero_bytes;
			child_aux->offs = parent_page->file.offs;
			succ = vm_alloc_page_with_initializer(page_get_type(parent_page), parent_page->va, parent_page->rw, 
			NULL, (void*)child_aux);
			if(succ == false){
				goto err;
			}
			succ = vm_claim_page(parent_page->va);
			if(succ == false){
				goto err;
			}
			struct page* child_page = spt_find_page(&thread_current()->spt, parent_page->va);
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
		}
		else{
			succ = vm_alloc_page(parent_type, parent_page->va, parent_page->rw);
			if(succ == false){
				goto err;
			}
			succ = vm_claim_page(parent_page->va);
			if(succ == false){
				goto err;
			}
			struct page* child_page = spt_find_page(&thread_current()->spt, parent_page->va);
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
		}
		hash_insert(&dst->spt_hash, iter.elem);
	}
	return true;
err:
	return false;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, &spt_clear_func);
}

//project3: vm -----------------------------------------------------

unsigned spt_hash_func(const struct hash_elem* e, void* aux){
	const struct page* target = hash_entry(e, struct page, hash_elem);
	return hash_bytes(&target->va, sizeof target->va);
}

bool spt_hash_less(const struct hash_elem* a, const struct hash_elem* b, void* aux){
	const struct page* pa = hash_entry(a, struct page, hash_elem);
	const struct page* pb = hash_entry(b, struct page, hash_elem);
	return pa->va < pb->va;
}

void spt_clear_func(struct hash_elem* e, void* aux){
	struct page* hash_page = hash_entry(e, struct page, hash_elem);
	destroy(hash_page);
	free(hash_page);
}
