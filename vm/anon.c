/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "bitmap.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);
	disk_sector_t swap_size = disk_size(swap_disk);
	swap_table = bitmap_create(swap_size);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	memset(&page->uninit, 0, sizeof(struct uninit_page));
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->swap_slot = BITMAP_ERROR;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	//lock_acquire(&swap_lock);
	int swap_slot = anon_page->swap_slot;
	if(swap_slot == BITMAP_ERROR){
		//lock_release(&swap_lock);
		return false;
	}
	bitmap_set_multiple(swap_table, swap_slot, SECTORS_PER_PAGE, false);
	for(int i = 0; i < SECTORS_PER_PAGE; i++){
		disk_read(swap_disk, swap_slot+i, kva+(i*DISK_SECTOR_SIZE));
	}
	anon_page->swap_slot = BITMAP_ERROR;
	pml4_set_page(thread_current()->pml4, page->va, kva, page->rw);
	//lock_release(&swap_lock);
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	//lock_acquire(&swap_lock);
	struct anon_page *anon_page = &page->anon;
	size_t empty_slot = bitmap_scan_and_flip(swap_table, 0, SECTORS_PER_PAGE, false);
	if(empty_slot == BITMAP_ERROR){
		//lock_release(&swap_lock);
		return false;
	}
	anon_page->swap_slot = empty_slot;
	for(int i = 0; i < SECTORS_PER_PAGE; i++){
		disk_write(swap_disk, empty_slot+i, page->frame->kva+(i*DISK_SECTOR_SIZE));
	}
	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(thread_current()->pml4, page->va);
	//lock_release(&swap_lock);
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if(anon_page->swap_slot != BITMAP_ERROR){
		bitmap_reset(swap_table, anon_page->swap_slot);
		anon_page->swap_slot = BITMAP_ERROR;
	}
	if(page->frame != NULL){
		list_remove(&page->frame->frame_elem);
		page->frame->page = NULL;
		free(page->frame);
		page->frame = NULL;
		//pml4_destroy함수에서 해당 frame palloc_free_page해준다.
	}

}
