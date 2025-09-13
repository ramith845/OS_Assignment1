#include "types.h"
#include "param.h"
#include "layout.h"
#include "riscv.h"
#include "defs.h"
#include "buf.h"
#include "elf.h"

#include <stdbool.h>

struct elfhdr* kernel_elfhdr;
struct proghdr* kernel_phdr;

uint64 find_kernel_load_addr(enum kernel ktype) {
    /* CSE 536: Get kernel load address from headers */
    if (ktype == NORMAL) {
        kernel_elfhdr = (struct elfhdr*) RAMDISK;
        kernel_phdr = (struct proghdr*)(RAMDISK + kernel_elfhdr->phoff + kernel_elfhdr->phentsize);
    }
    else {
        kernel_elfhdr = (struct elfhdr*) RECOVERYDISK;
    }
    return kernel_phdr->vaddr;
}

uint64 find_kernel_size(enum kernel ktype) {
    /* CSE 536: Get kernel binary size from headers */
    if (ktype == NORMAL) {
        return kernel_elfhdr->shoff + (uint64)(kernel_elfhdr->shentsize * kernel_elfhdr->shnum);
    }
    else {
        return 0;
    }
}

uint64 find_kernel_entry_addr(enum kernel ktype) {
    /* CSE 536: Get kernel entry point from headers */
    
    return kernel_elfhdr->entry;
}