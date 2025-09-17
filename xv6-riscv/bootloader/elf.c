#include "types.h"
#include "param.h"
#include "layout.h"
#include "riscv.h"
#include "defs.h"
#include "buf.h"
#include "elf.h"

#include <stdbool.h>

struct elfhdr *kernel_elfhdr;
struct proghdr *kernel_phdr;

uint64 base_addr(enum kernel ktype) {
  return ktype == NORMAL ? RAMDISK : RECOVERYDISK;
}

uint64 find_kernel_load_addr(enum kernel ktype) {
  /* CSE 536: Get kernel load address from headers */
  uint64 base = base_addr(ktype);
  kernel_elfhdr = (struct elfhdr *)base_addr(ktype);
  // kernel_phdr = (struct proghdr*)(base + kernel_elfhdr->phoff +
  // kernel_elfhdr->phentsize);
  kernel_phdr = (struct proghdr *)(base + kernel_elfhdr->phoff);
  for (int i = 0; i < kernel_elfhdr->phnum; i++) {
    if (kernel_phdr[i].type == ELF_PROG_LOAD) {
      return kernel_phdr[i].vaddr;
    }
  }
  return 0;
}

uint64 find_kernel_size(enum kernel ktype) {
  /* CSE 536: Get kernel binary size from headers */
  uint64 base = base_addr(ktype);
  kernel_elfhdr = (struct elfhdr *)base_addr(ktype);
  kernel_phdr = (struct proghdr *)(base + kernel_elfhdr->phoff);
  uint64 ph_off_end = 0;
  for (int i = 0; i < kernel_elfhdr->phnum; i++) {
    uint64 seg_end = kernel_phdr[i].off + kernel_phdr[i].filesz;
    if (seg_end > ph_off_end) {
      ph_off_end = seg_end;
    }
  }
  uint64 sh_off_end = kernel_elfhdr->shoff +
                      (uint64)(kernel_elfhdr->shentsize * kernel_elfhdr->shnum);
  return sh_off_end > ph_off_end ? sh_off_end : ph_off_end;
}

uint64 find_kernel_entry_addr(enum kernel ktype) {
  /* CSE 536: Get kernel entry point from headers */
  kernel_elfhdr = (struct elfhdr *)base_addr(ktype);
  return kernel_elfhdr->entry;
}