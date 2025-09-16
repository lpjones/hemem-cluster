#ifndef HEMEM_H

#define HEMEM_H

#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>

#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
#define _Atomic(X) std::atomic< X >
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ALLOC_LRU
#include "policies/lru.h"
#endif

#ifdef ALLOC_SIMPLE
#include "policies/simple.h"
#endif 

#include "pebs.h"
#include "timer.h"
#include "interpose.h"
#include "uthash.h"
#include "fifo.h"

//#define HEMEM_DEBUG
#define STATS_THREAD

// #define USE_DMA
#define NUM_CHANNS 2
#define SIZE_PER_DMA_REQUEST (1024*1024)

#define MEM_BARRIER() __sync_synchronize()

extern uint64_t nvmsize;
extern uint64_t dramsize;
extern off_t nvmoffset;
extern off_t dramoffset;
extern char* drampath;
extern char* nvmpath;
extern uint64_t hemem_start_cpu;
extern uint64_t num_cores;
extern uint64_t fault_thread_cpu;
extern uint64_t stats_thread_cpu;
extern pid_t main_thread;
extern pthread_mutex_t pages_lock;
extern pthread_mutex_t change_page_lock;

extern FILE* miss_ratio_f;
extern _Atomic bool miss_ratio_f_opened;
extern _Atomic int internal_call;

#define NVMSIZE_DEFAULT   (19L * (1024L * 1024L * 1024L))
// #define DRAMSIZE_DEFAULT  (2L * (1024L * 1024L))
#define DRAMSIZE_DEFAULT  (2L * (1024L * 1024L * 1024L))

#define NVMOFFSET_DEFAULT (0)
#define DRAMOFFSET_DEFAULT (0)

#define DRAMPATH_DEFAULT  "/dev/dax0.0"
#define NVMPATH_DEFAULT   "/dev/dax1.0"

//#define PAGE_SIZE (1024 * 1024 * 1024)
//#define PAGE_SIZE (2 * (1024 * 1024))
// #define BASEPAGE_SIZE	  (4UL * 1024UL)
// #define HUGEPAGE_SIZE 	(2UL * 1024UL * 1024UL)
// #define GIGAPAGE_SIZE   (1024UL * 1024UL * 1024UL)
#ifndef PAGE_SIZE
  #define PAGE_SIZE 	    (2UL * 1024UL * 1024UL)
#endif
#define LOG_PAGE_SIZE     (63 - __builtin_clzll(PAGE_SIZE))
// #define BASEPAGE_MASK	(BASEPAGE_SIZE - 1)
// #define HUGEPAGE_MASK	(HUGEPAGE_SIZE - 1)
// #define GIGAPAGE_MASK   (GIGAPAGE_SIZE - 1)
#define PAGE_MASK (PAGE_SIZE - 1)

// #define BASE_PFN_MASK	(BASEPAGE_MASK ^ UINT64_MAX)
// #define HUGE_PFN_MASK	(HUGEPAGE_MASK ^ UINT64_MAX)
// #define GIGA_PFN_MASK   (GIGAPAGE_MASK ^ UINT64_MAX)
#define PAGE_PFN_MASK (PAGE_MASK ^ UINT64_MAX)

#define START_THREAD_DEFAULT 0
#define FAULT_THREAD_CPU_DEFAULT  (START_THREAD_DEFAULT)
#define STATS_THREAD_CPU_DEFAULT  (START_THREAD_DEFAULT)

extern uint64_t fault_thread_cpu;
extern uint64_t stats_thread_cpu;

extern FILE *hememlogf;
//#define LOG(...) fprintf(stderr, __VA_ARGS__)
#define LOG(...)	{ fprintf(hememlogf, __VA_ARGS__); fflush(hememlogf); }
//#define LOG(str, ...) while(0) {}

extern FILE *timef;
extern _Atomic bool timing;

struct __attribute__((__packed__)) mig_record {
  double val;
  uint8_t type;
};

enum mig_types {
  MEMCPY_TO_DRAM = 0,
  MMAP_DRAM1 = 1,
  UFFDIO_REGISTER1 = 2,
  HEMEM_MIGRATE_UP = 3,
  MEMCPY_TO_NVM = 4,
  MMAP_NVM1 = 5,
  HEMEM_MIGRATE_DOWN = 6,
  UFFDIO_WRITEPROTECT1 = 7,
  PAGE_FAULT = 8,
  MMAP_DRAM = 9,
  MMAP_NVM = 10,
  HEMEM_MISSING_FAULT = 11,
  UFFDIO_REGISTER2 = 12,
  UFFDIO_REGISTER3 = 13,
  MIGRATE_DOWN = 14,
  MIGRATE_UP = 15,
  MIGRATE = 16,
  MEM_POLICY_ALLOCATE_PAGE1 = 17,
  MEM_POLICY_ALLOCATE_PAGE2 = 18,
  MIG_QUEUE_DELAY_UP = 19,
  MIG_QUEUE_DELAY_DOWN = 20,
  NMIGTYPES
};

static inline void log_time(uint8_t type, double val)
{
  struct mig_record rec = { .val = val, .type = type };
  write(fileno(timef), &rec, sizeof(struct mig_record));
}


//#define LOG_TIME(str, ...) log_time(str, __VA_ARGS__)
//#define LOG_TIME(str, ...) fprintf(timef, str, __VA_ARGS__)
// #define LOG_TIME(str, ...) while(0) {}
#define LOG_TIME(type, val) log_time(type, val)

extern FILE *statsf;
//#define LOG_STATS(str, ...) fprintf(stderr, str, __VA_ARGS__)
#define LOG_STATS(str, ...) { fprintf(statsf, str, __VA_ARGS__); fflush(statsf); }
//#define LOG_STATS(str, ...) while (0) {}

#if defined (ALLOC_HEMEM)
  #define pagefault(...) pebs_pagefault(__VA_ARGS__)
  #define paging_init(...) pebs_init(__VA_ARGS__)
  #define mmgr_remove(...) pebs_remove_page(__VA_ARGS__)
  #define mmgr_stats(...) pebs_stats(__VA_ARGS__)
  #define policy_shutdown(...) pebs_shutdown(__VA_ARGS__)
#elif defined (ALLOC_LRU)
  #define pagefault(...) lru_pagefault(__VA_ARGS__)
  #define paging_init(...) lru_init(__VA_ARGS__)
  #define mmgr_remove(...) lru_remove_page(__VA_ARGS__)
  #define mmgr_stats(...) lru_stats(__VA_ARGS__)
  #define policy_shutdown(...) while(0) {}
#elif defined (ALLOC_SIMPLE)
  #define pagefault(...) simple_pagefault(__VA_ARGS__)
  #define paging_init(...) simple_init(__VA_ARGS__)
  #define mmgr_remove(...) simple_remove_page(__VA_ARGS__)
  #define mmgr_stats(...) simple_stats(__VA_ARGS__)
  #define policy_shutdown(...) while(0) {}
#endif


#define MAX_UFFD_MSGS	    (1)
#define MAX_COPY_THREADS  (4)

extern uint64_t cr3;
extern int dramfd;
extern int nvmfd;
extern _Atomic bool is_init;
extern _Atomic uint64_t missing_faults_handled;
extern _Atomic uint64_t migrations_up;
extern _Atomic uint64_t migrations_down;
extern __thread bool internal_malloc;
extern __thread bool internal_munmap;

enum memtypes {
  FASTMEM = 0,
  SLOWMEM = 1,
  NMEMTYPES,
};

enum pagetypes {
  HUGEP = 0,
  BASEP = 1,
  NPAGETYPES
};

struct hemem_page {
  uint64_t accesses[NPBUFTYPES];
  uint64_t tot_accesses[NPBUFTYPES];
  uint64_t va;
  uint64_t devdax_offset;
  uint64_t naccesses;
  uint64_t migrations_up, migrations_down;
  uint64_t local_clock;

  pthread_mutex_t page_lock;
  enum pagetypes pt;
  UT_hash_handle hh;
  struct hemem_page *next, *prev;
  struct fifo_list *list;
  struct timeval mig_start;

  volatile bool migrating;
  bool ring_present;
  bool in_dram;
  bool present;
  bool written;
  bool hot;
};

// static inline uint64_t pt_to_pagesize(enum pagetypes pt)
// {
//   switch(pt) {
//   case HUGEP: return HUGEPAGE_SIZE;
//   case BASEP: return BASEPAGE_SIZE;
//   default: assert(!"Unknown page type");
//   }
// }

static inline uint64_t pt_to_pagesize(enum pagetypes pt)
{
  return PAGE_SIZE;
}

// static inline enum pagetypes pagesize_to_pt(uint64_t pagesize)
// {
//   switch (pagesize) {
//     case BASEPAGE_SIZE: return BASEP;
//     case HUGEPAGE_SIZE: return HUGEP;
//     default: assert(!"Unknown page ssize");
//   }
// }

static inline enum pagetypes pagesize_to_pt(uint64_t pagesize)
{
  switch (pagesize) {
    case PAGE_SIZE: return BASEP;
    default: assert(!"Unknown page ssize");
  }
  return BASEP;
}

void hemem_init();
void hemem_stop();
void* hemem_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int hemem_munmap(void* addr, size_t length);
void *handle_fault();
void hemem_migrate_up(struct hemem_page *page, uint64_t dram_offset);
void hemem_migrate_down(struct hemem_page *page, uint64_t nvm_offset);
struct hemem_page* find_page(uint64_t va);
void hemem_wp_page(struct hemem_page *page, bool protect);
void hemem_promote_pages(uint64_t addr);
void hemem_demote_pages(uint64_t addr);

#ifdef ALLOC_LRU
void hemem_clear_bits(struct hemem_page *page);
uint64_t hemem_get_bits(struct hemem_page *page);
void hemem_tlb_shootdown(uint64_t va);
#endif

struct hemem_page* get_hemem_page(uint64_t va);

void hemem_print_stats(FILE *fd);
void hemem_clear_stats();
void hemem_clear_stats_full();

void hemem_start_timing(void);
void hemem_stop_timing(void);

#ifdef __cplusplus
}
#endif

#endif /* HEMEM_H */
