/* These files have been taken from the open-source xv6 Operating System codebase (MIT License).  */

#include "types.h"
#include "param.h"
#include "layout.h"
#include "riscv.h"
#include "defs.h"
#include "buf.h"
#include "measurements.h"
#include <stdbool.h>

void main();
void timerinit();

/* entry.S needs one stack per CPU */
__attribute__ ((aligned (16))) char bl_stack[STSIZE * NCPU];

/* Context (SHA-256) for secure boot */
SHA256_CTX sha256_ctx;

/* Structure to collects system information */
struct sys_info {
  /* Bootloader binary addresses */
  uint64 bl_start;
  uint64 bl_end;
  /* Accessible DRAM addresses (excluding bootloader) */
  uint64 dr_start;
  uint64 dr_end;
  /* Kernel SHA-256 hashes */
  BYTE expected_kernel_measurement[32];
  BYTE observed_kernel_measurement[32];
};
struct sys_info* sys_info_ptr;

extern void _entry(void);
void panic(char *s)
{
  for(;;)
    ;
}

/* CSE 536: Boot into the RECOVERY kernel instead of NORMAL kernel
 * when hash verification fails. */
void setup_recovery_kernel(void) {
}

/* CSE 536: Function verifies if NORMAL kernel is expected or tampered. */
bool is_secure_boot(void) {
  bool verification = true;

  /* Read the binary and update the observed measurement 
   * (simplified template provided below) */
  sha256_init(&sha256_ctx);
  struct buf b;
  sha256_update(&sha256_ctx, (const unsigned char*) b.data, BSIZE);
  sha256_final(&sha256_ctx, sys_info_ptr->observed_kernel_measurement);

  /* Three more tasks required below: 
   *  1. Compare observed measurement with expected hash
   *  2. Setup the recovery kernel if comparison fails
   *  3. Copy expected kernel hash to the system information table */
  if (!verification)
    setup_recovery_kernel();
  
  return verification;
}

uint64 to_napot_addr(uint64 base, uint64 top)
{
  uint64 size = top - base;
  return (base>>2) | (size/2 - 1);
}

uint64 to_tor_addr(uint64 addr)
{
  return addr >> 2;
}

// entry.S jumps here in machine mode on stack0.
void start()
{
  /* CSE 536: Define the system information table's location. */
  sys_info_ptr = (struct sys_info*) 0x80080000;
  sys_info_ptr->bl_start = (uint64)KERNBASE;
  sys_info_ptr->bl_end = (uint64)&end;  
  sys_info_ptr->dr_start = (uint64)KERNBASE; // No need for +1
  sys_info_ptr->dr_end = (uint64)PHYSTOP;
  // keep each CPU's hartid in its tp register, for cpuid().
  int id = r_mhartid();
  w_tp(id);

  // set M Previous Privilege mode to Supervisor, for mret.
  unsigned long x = r_mstatus();
  // zero out 11th and 12th bit
  // Machine previous privilege mode.
  // Machine: 11, Supervisor: 01, User: 00
  x &= ~MSTATUS_MPP_MASK;
  // make MPP bits 01 for S-mode
  x |= MSTATUS_MPP_S;
  w_mstatus(x);

  // disable paging
  w_satp(0);

/* CSE 536: Unless kernelpmp[1-2] booted, allow all memory
 * regions to be accessed in S-mode. */
#if !defined(KERNELPMP1) || !defined(KERNELPMP2)
  // w_pmpaddr0(0x3fffffffffffffull);
  // w_pmpcfg0(0xf);
#endif

/* CSE 536: With kernelpmp1, isolate upper 10MBs using TOR */
#if defined(KERNELPMP1)
  // TOR: 118 MB
  // w_pmpaddr0(0x21d40000ull);
  w_pmpaddr0(to_tor_addr(0x87500000ull));
  // R/W/X with TOR
  w_pmpcfg0(0xf);
#endif

/* CSE 536: With kernelpmp2, isolate 118-120 MB and 122-126 MB using NAPOT */
#if defined(KERNELPMP2)
// R/W/X with TOR
  w_pmpaddr0(to_tor_addr(0x87600000ull));
  w_pmpcfg0(0xf);

  // 118-120 deny:  0x87600000 to 0x87800000
  // w_pmpaddr1(0x21dbffff);
  // w_pmpcfg1(0x18);
  // 120-122 allow: 0x87800000 to 0x87a00000
  w_pmpaddr0(to_napot_addr(0x80000000ull, 0x87a00000ull));
  w_pmpcfg0(0x1f);
  // // 122-126 deny: 0x87a00000 to 0x87e00000
  // w_pmpaddr3(to_napot_addr(0x87a00000ull, 0x87e00000ull));
  // w_pmpcfg3(0x18);
  // // 126-128 allow: 0x87e00000 to 0x88000000
  // w_pmpaddr4(to_napot_addr(0x87e00000ull, 0x88000000ull));
  // w_pmpcfg4(0x1f);
#endif

  /* CSE 536: Verify if the kernel is untampered for secure boot */
  if (!is_secure_boot()) {
    /* Skip loading since we should have booted into a recovery kernel 
     * in the function is_secure_boot() */
    goto out;
  }
  
  /* CSE 536: Load the NORMAL kernel binary (assuming secure boot passed). */
  uint64 kernel_load_addr       = find_kernel_load_addr(NORMAL);
  uint64 kernel_binary_size     = find_kernel_size(NORMAL);     
  uint64 kernel_entry           = find_kernel_entry_addr(NORMAL);
  
  struct buf b;
  /*
    say kernel_binary_size = 4050
    blocks = 4050 / 1000 = 4
    roundup to 5 not 4 for extra 50 bytes 
    (kernel_binary_size + BSIZE - 1 )/ BSIZE = (4050 + 1000 - 1) / 1000 = 5
  */
  uint64 blocks = (kernel_binary_size + (uint64)BSIZE - 1) / BSIZE;
  uint64 copied = 0;
  int block_start = 4;
  for (int i = block_start; i < blocks; i++) 
  {
    b.blockno = i;
    kernel_copy(NORMAL, &b);

    uint64 rem = kernel_binary_size - copied;
    uint chunk = BSIZE;
    if (rem < BSIZE) chunk = rem;
    if (kernel_load_addr == 0) panic(0x0);
    memmove((char*)(kernel_load_addr + copied), &b.data, chunk);
    copied += chunk;
  }


  /* CSE 536: Write the correct kernel entry point */
  w_mepc((uint64) kernel_entry);
 
 out:
  /* CSE 536: Provide system information to the kernel. */

  /* CSE 536: Send the observed hash value to the kernel (using sys_info_ptr) */

  // delegate all interrupts and exceptions to supervisor mode.
  w_medeleg(0xffff);
  w_mideleg(0xffff);
  w_sie(r_sie() | SIE_SEIE | SIE_STIE | SIE_SSIE);

  // switch to supervisor mode and jump to main().
  asm volatile("mret");
}