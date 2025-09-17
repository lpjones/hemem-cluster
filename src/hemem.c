#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <math.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sched.h>

#include <malloc.h>

#include "hemem.h"
#include "timer.h"
#include "uthash.h"
#include "pebs.h"

#ifdef ALLOC_LRU
#include "policies/paging.h"
#endif

pthread_t fault_thread;

uint64_t nvmsize = 0;
uint64_t dramsize = 0;
off_t nvmoffset = 0;
off_t dramoffset = 0;
char* drampath = NULL;
char* nvmpath = NULL;

uint64_t hemem_start_cpu = 0;
uint64_t num_cores = 0;

uint64_t fault_thread_cpu = 0;
uint64_t stats_thread_cpu = 0;

int dramfd = -1;
int nvmfd = -1;
long uffd = -1;

_Atomic bool is_init = false;
_Atomic bool timing = false;
_Atomic int internal_call = 0;

_Atomic uint64_t mem_mmaped = 0;
_Atomic uint64_t mem_allocated = 0;
_Atomic uint64_t pages_allocated = 0;
_Atomic uint64_t pages_freed = 0;
_Atomic uint64_t fastmem_allocated = 0;
_Atomic uint64_t slowmem_allocated = 0;
_Atomic uint64_t wp_faults_handled = 0;
_Atomic uint64_t missing_faults_handled = 0;
_Atomic uint64_t migrations_up = 0;
_Atomic uint64_t migrations_down = 0;
_Atomic uint64_t bytes_migrated = 0;
_Atomic uint64_t memcpys = 0;
_Atomic uint64_t memsets = 0;
_Atomic uint64_t migration_waits = 0;
pid_t main_thread = 0;

static bool cr3_set = false;
uint64_t cr3 = 0;

FILE* hememlogf;
FILE* statsf;
FILE* timef;
FILE* record_fp;

#ifndef USE_DMA
pthread_t copy_threads[MAX_COPY_THREADS];
#endif
pthread_t stats_thread;

struct hemem_page *pages = NULL;
// pthread_mutex_t pages_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pages_lock;
pthread_mutex_t change_page_lock = PTHREAD_MUTEX_INITIALIZER;


void *dram_devdax_mmap;
void *nvm_devdax_mmap;

#ifndef USE_DMA
struct pmemcpy {
  pthread_mutex_t lock;
  pthread_barrier_t barrier;
  _Atomic bool write_zeros;
  _Atomic void *dst;
  _Atomic void *src;
  _Atomic size_t length;
};

static struct pmemcpy pmemcpy;

void *hemem_parallel_memcpy_thread(void *arg)
{
  uint64_t tid = (uint64_t)arg;
  void *src;
  void *dst;
  size_t length;
  size_t chunk_size;

  assert(tid < MAX_COPY_THREADS);
  

  for (;;) {
    /* while(!pmemcpy.activate || pmemcpy.done_bitmap[tid]) { } */
    int r = pthread_barrier_wait(&pmemcpy.barrier);
    assert(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
    if (tid == 0) {
      memcpys++;
    }

    // grab data out of shared struct
    length = pmemcpy.length;
    chunk_size = length / MAX_COPY_THREADS;
    dst = pmemcpy.dst + (tid * chunk_size);
    if (!pmemcpy.write_zeros) {
      src = pmemcpy.src + (tid * chunk_size);
      memcpy(dst, src, chunk_size);
    }
    else {
      memset(dst, 0, chunk_size);
    }

#ifdef HEMEM_DEBUG
    uint64_t *tmp1, *tmp2, i;
    tmp1 = dst;
    tmp2 = src;
    for (i = 0; i < chunk_size / sizeof(uint64_t); i++) {
      if (tmp1[i] != tmp2[i]) {
        LOG("copy thread: dst[%lu] = %lu != src[%lu] = %lu\n", i, tmp1[i], i, tmp2[i]);
        assert(tmp1[i] == tmp2[i]);
      }
    }
#endif

    //LOG("thread %lu done copying\n", tid);

    r = pthread_barrier_wait(&pmemcpy.barrier);
    assert(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
    /* pmemcpy.done_bitmap[tid] = true; */
  }
  return NULL;
}
#endif

static void *hemem_stats_thread()
{
  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(STATS_THREAD_CPU_DEFAULT, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }
  while (!miss_ratio_f_opened) {
    sleep(1);
  }

  for (;;) {
    sleep(1);
    
    hemem_print_stats(stderr);
    hemem_clear_stats();
  }
  return NULL;
}

void add_page(struct hemem_page *page)
{
  struct hemem_page *p;
  pthread_mutex_lock(&pages_lock);
  HASH_FIND(hh, pages, &(page->va), sizeof(uint64_t), p);
  if (p != NULL) {
    // printf("HeMem page already exists: 0x%lx\n", page->va);
    LOG("HeMem page already exists: 0x%lx\n", page->va);
    pthread_mutex_unlock(&pages_lock);
    return;
  }
  assert(p == NULL);
  HASH_ADD(hh, pages, va, sizeof(uint64_t), page);
  pthread_mutex_unlock(&pages_lock);
}

void remove_page(struct hemem_page *page)
{
  // printf("Removing HeMem page: 0x%lx\n", page->va);

  pthread_mutex_lock(&pages_lock);
  HASH_DEL(pages, page);
  pthread_mutex_unlock(&pages_lock);
}

struct hemem_page* find_page(uint64_t va)
{
  struct hemem_page *page;
  pthread_mutex_lock(&pages_lock);
  HASH_FIND(hh, pages, &va, sizeof(uint64_t), page);
  pthread_mutex_unlock(&pages_lock);
  return page;
}


void hemem_init()
{
  if (is_init) return;
  struct uffdio_api uffdio_api;
#ifdef USE_DMA
  struct uffdio_dma_channs uffdio_dma_channs;
#endif
  char logpath[32];

  internal_call++;
  main_thread = getpid();

/*
  {
    // This call is dangerous. Ideally, all printf's should be
    // replaced with logging macros that can print to stderr instead
    // (which is unbuffered).
    int r = setvbuf(stdout, NULL, _IONBF, 0);
    assert(r == 0);
  }
*/
  char* hemem_start_cpu_string = getenv("HEMEM_MGR_START_CPU");
  if(hemem_start_cpu_string != NULL)
    hemem_start_cpu = strtoull(hemem_start_cpu_string, NULL, 10);
  else
    hemem_start_cpu = START_THREAD_DEFAULT;

  stats_thread_cpu = hemem_start_cpu;
  fault_thread_cpu = hemem_start_cpu;

  char* num_cores_string = getenv("HEMEM_NUM_CORES");
  if(num_cores_string != NULL)
    num_cores = strtoull(num_cores_string, NULL, 10);
  else
    num_cores = PEBS_NPROCS;

  snprintf(&logpath[0], sizeof(logpath) - 1, "debuglog-hem.txt");
  hememlogf = fopen(logpath, "w+");
  if (hememlogf == NULL) {
    perror("log file open\n");
    assert(0);
  }

  LOG("hemem_init: started\n");

  drampath = getenv("DRAMPATH");
  if(drampath == NULL) {
    drampath = malloc(sizeof(DRAMPATH_DEFAULT));
    strcpy(drampath, DRAMPATH_DEFAULT);
  }

  dramfd = open(drampath, O_RDWR);
  if (dramfd < 0) {
    perror("dram open");
  }
  assert(dramfd >= 0);

  nvmpath = getenv("NVMPATH");
  if(nvmpath == NULL) {
    nvmpath = malloc(sizeof(NVMPATH_DEFAULT));
    strcpy(nvmpath, NVMPATH_DEFAULT);
  }

  nvmfd = open(nvmpath, O_RDWR);
  if (nvmfd < 0) {
    perror("nvm open");
  }
  assert(nvmfd >= 0);

  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) {
    perror("uffd");
    assert(0);
  }

  uffdio_api.api = UFFD_API;
  uffdio_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP |  UFFD_FEATURE_MISSING_SHMEM | UFFD_FEATURE_MISSING_HUGETLBFS;// | UFFD_FEATURE_EVENT_UNMAP | UFFD_FEATURE_EVENT_REMOVE;
  uffdio_api.ioctls = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
    perror("ioctl uffdio_api");
    assert(0);
  }

  int s = pthread_create(&fault_thread, NULL, handle_fault, 0);
  if (s != 0) {
    perror("pthread_create");
    assert(0);
  }

  timef = fopen("times-hem.bin", "w+");
  if (timef == NULL) {
    perror("time file fopen\n");
    assert(0);
  }

  record_fp = fopen("trace-hem.bin", "w+");
  if (record_fp == NULL) {
    perror("record file fopen\n");
    assert(0);
  }

  char stats_name_buf[25]; 
  int snret = snprintf(stats_name_buf, 25, "stats-hem.txt");
  assert(snret > 0);
  statsf = fopen(stats_name_buf, "w+");
  if (statsf == NULL) {
    perror("stats file fopen\n");
    assert(0);
  }

  char* dramoffset_string = getenv("DRAMOFFSET");
  if(dramoffset_string != NULL)
    dramoffset = strtoull(dramoffset_string, NULL, 10);
  else
    dramoffset = DRAMOFFSET_DEFAULT;

  char* dramsize_string = getenv("DRAMSIZE");
  if(dramsize_string != NULL)
    dramsize = strtoull(dramsize_string, NULL, 10);
  else
    dramsize = DRAMSIZE_DEFAULT;
  LOG("mapping DRAM\n");
  if(dramsize != 0) {
    dram_devdax_mmap =libc_mmap(NULL, dramsize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, dramfd, dramoffset);
    if (dram_devdax_mmap == MAP_FAILED) {
      perror("dram devdax mmap");
      assert(0);
    }
  }
  LOG("Finished mapping DRAM\n");

  char* nvmoffset_string = getenv("NVMOFFSET");
  if(nvmoffset_string != NULL)
    nvmoffset = strtoull(nvmoffset_string, NULL, 10);
  else
    nvmoffset = NVMOFFSET_DEFAULT;

  char* nvmsize_string = getenv("NVMSIZE");
  if(nvmsize_string != NULL)
    nvmsize = strtoull(nvmsize_string, NULL, 10);
  else
    nvmsize = NVMSIZE_DEFAULT;
  LOG("mapping NVM\n");
  nvm_devdax_mmap =libc_mmap(NULL, nvmsize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, nvmfd, nvmoffset);
  if (nvm_devdax_mmap == MAP_FAILED) {
    perror("nvm devdax mmap");
    assert(0);
  }
  LOG("Finished mapping NVM\n");

#ifndef USE_DMA 
  uint64_t i;
  int r = pthread_barrier_init(&pmemcpy.barrier, NULL, MAX_COPY_THREADS + 1);
  assert(r == 0);

  r = pthread_mutex_init(&pmemcpy.lock, NULL);
  assert(r == 0);

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  r = pthread_mutex_init(&pages_lock, &attr);

  for (i = 0; i < MAX_COPY_THREADS; i++) {
    s = pthread_create(&copy_threads[i], NULL, hemem_parallel_memcpy_thread, (void*)i);
    assert(s == 0);
  }
#endif

#ifdef STATS_THREAD
  s = pthread_create(&stats_thread, NULL, hemem_stats_thread, NULL);
  assert(s == 0);
#endif
  LOG("Doing paging_init()\n");
  paging_init();
  LOG("Finished paging_init()\n");

  
  LOG("hemem: initialization complete\n");

  struct hemem_page *dummy_page = calloc(1, sizeof(struct hemem_page));
  add_page(dummy_page);

  __sync_synchronize();
  is_init = true;

#ifdef USE_DMA
  uffdio_dma_channs.num_channs = NUM_CHANNS;
  uffdio_dma_channs.size_per_dma_request = SIZE_PER_DMA_REQUEST;
  if (ioctl(uffd, UFFDIO_DMA_REQUEST_CHANNS, &uffdio_dma_channs) == -1) {
      printf("ioctl UFFDIO_API fails\n");
      exit(1);
  }
#endif

  LOG("hemem_init: finished\n");

  internal_call--;
}


void hemem_stop()
{
#ifdef USE_DMA
  struct uffdio_dma_channs uffdio_dma_channs;
  uffdio_dma_channs.num_channs = NUM_CHANNS;
  uffdio_dma_channs.size_per_dma_request = SIZE_PER_DMA_REQUEST;
  if (ioctl(uffd, UFFDIO_DMA_RELEASE_CHANNS, &uffdio_dma_channs) == -1) {
    perror("ioctl UFFDIO_RELEASE_CHANNS");
    assert(0);
  }
#endif

  policy_shutdown();

}

#ifndef USE_DMA
static void hemem_parallel_memset(void* addr, int c, size_t n)
{
  pthread_mutex_lock(&(pmemcpy.lock));
  pmemcpy.dst = addr;
  pmemcpy.length = n;
  pmemcpy.write_zeros = true;

  int r = pthread_barrier_wait(&pmemcpy.barrier);
  assert(r ==0 || r == PTHREAD_BARRIER_SERIAL_THREAD);

  r = pthread_barrier_wait(&pmemcpy.barrier);
  assert(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
  
  pthread_mutex_unlock(&(pmemcpy.lock));
}
#endif

static void hemem_mmap_populate(void* addr, size_t length)
{
  // Page mising fault case - probably the first touch case
  // allocate in DRAM via LRU
  void* newptr;
  uint64_t offset;
  struct hemem_page *page;
  bool in_dram;
  uint64_t page_boundry;
  void* tmpaddr;
  uint64_t pagesize;

  assert(addr != 0);
  assert(length != 0);
  // printf("addr: %p, length: %zu\n", addr, length);

  for (page_boundry = (uint64_t)addr; page_boundry < (uint64_t)addr + length;) {
    page = pagefault();
    assert(page != NULL);
    // let policy algorithm do most of the heavy lifting of finding a free page
    offset = page->devdax_offset;
    in_dram = page->in_dram;
    pagesize = pt_to_pagesize(page->pt);
    // printf("page size: %zu\n", pagesize);

    tmpaddr = (in_dram ? dram_devdax_mmap + (offset - dramoffset): nvm_devdax_mmap + (offset - nvmoffset));
#ifndef USE_DMA
    hemem_parallel_memset(tmpaddr, 0, pagesize);
#else
#ifdef LLAMA
    memset(tmpaddr, 0, pagesize);
#endif
#endif
    memsets++;
  
    // now that we have an offset determined via the policy algorithm, actually map
    // the page for the application
    // fprintf(stderr, "hemem: mmap populate: mapping page 0x%lx, size %zu\n", page_boundry, pagesize);
    newptr = libc_mmap((void*)page_boundry, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_FIXED, (in_dram ? dramfd : nvmfd), offset);
    if (newptr == MAP_FAILED) {
      perror("hemem_mmap_populate: newptr mmap");
      assert(0);
    }
    // printf("New HeMem page: 0x%p\n", newptr);
  
    if (newptr != (void*)page_boundry) {
      fprintf(stderr, "hemem: mmap populate: warning, newptr != page boundry\n");
    }

    // re-register new mmap region with userfaultfd
    struct uffdio_register uffdio_register;
    uffdio_register.range.start = (uint64_t)newptr;
    uffdio_register.range.len = pagesize;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
    uffdio_register.ioctls = 0;
    // LOG("hemem_mmap_populate: registering page 0x%lx, size %zu with uffd\n", (uint64_t)newptr, pagesize);
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
      perror("ioctl uffdio_register");
      assert(0);
    } // mmap_populate

    // use mmap return addr to track new page's virtual address
    page->va = (uint64_t)newptr;
    // printf("New HeMem page: 0x%lx\n", page->va);
    // printf("page boundry: 0x%lx\n", page_boundry);
    // printf("length: %zu\n", length);
    assert(page->va != 0);
    assert(page->va % PAGE_SIZE == 0);
    page->migrating = false;
    page->migrations_up = page->migrations_down = 0;
    struct timeval null_mig = {0};
    page->mig_start = null_mig;
    //page->pa = hemem_va_to_pa(page);
 
    pthread_mutex_init(&(page->page_lock), NULL);

    mem_allocated += pagesize;
    pages_allocated++;

    // place in hemem's page tracking list
    add_page(page);
    page_boundry += pagesize;
    pthread_mutex_unlock(&page->page_lock);
  }

}

#define PAGE_ROUND_UP(x) (((x) + (PAGE_SIZE)-1) & (~((PAGE_SIZE)-1)))

void* hemem_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
  void *p;
  struct uffdio_cr3 uffdio_cr3;

  internal_call++;
  assert(is_init);
  assert(length != 0);
  
  if ((flags & MAP_PRIVATE) == MAP_PRIVATE) {
    flags &= ~MAP_PRIVATE;
    flags |= MAP_SHARED;
    LOG("hemem_mmap: changed flags to MAP_SHARED\n");
  }

  if ((flags & MAP_ANONYMOUS) == MAP_ANONYMOUS) {
    flags &= ~MAP_ANONYMOUS;
    LOG("hemem_mmap: unset MAP_ANONYMOUS\n");
  }

  if ((flags & MAP_HUGETLB) == MAP_HUGETLB) {
    flags &= ~MAP_HUGETLB;
    LOG("hemem_mmap: unset MAP_HUGETLB\n");
  }
  
  // reserve block of memory
  length = PAGE_ROUND_UP(length);
  p = libc_mmap(addr, length, prot, flags, dramfd, offset + dramoffset);
  if (p == NULL || p == MAP_FAILED) {
    perror("mmap");
  }
  assert(p != NULL && p != MAP_FAILED);

  // register with uffd
  struct uffdio_register uffdio_register;
  uffdio_register.range.start = (uint64_t)p;
  uffdio_register.range.len = length;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
  uffdio_register.ioctls = 0;
  // printf("addr: %p, length: %zu, mem_allocated: %zu\n", p, length, mem_allocated);
  // printf("uffd: %ld, start: %lx, len: %zu pages: %zu mem_allocated: %zu\n", 
  //       uffd, (uint64_t)p, length, pages_allocated - pages_freed, mem_allocated);

  // LOG("hemem_mmap: registering region 0x%lx, len %zu with uffd\n", (uint64_t)p, length);
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
    perror("ioctl uffdio_register");
    printf("in hemem_mmap: uffd: %ld, start: %lx, len: %zu\n", uffd, (uint64_t)p, length);
    assert(0);
  }

  if (!cr3_set) {
    LOG("hemem_mmap: getting cr3\n");
    if (ioctl(uffd, UFFDIO_CR3, &uffdio_cr3) < 0) {
      perror("ioctl uffdio_cr3");
      assert(0);
    }
    cr3 = uffdio_cr3.cr3;
    cr3_set = true;
  }

   
//  if ((flags & MAP_POPULATE) == MAP_POPULATE) {
    hemem_mmap_populate(p, length);
//  }

  mem_mmaped = length;
  
  internal_call--;
  
  return p;
}


int hemem_munmap(void* addr, size_t length)
{
  uint64_t page_boundry;
  struct hemem_page *page;
  int ret;

  internal_call++;


  //fprintf(stderr, "munmap(%p, %lu)\n", addr, length);

  // for each page in region specified...
  for (page_boundry = (uint64_t)addr; page_boundry < (uint64_t)addr + length;) {
    // find the page in hemem's trackign list
    pthread_mutex_lock(&change_page_lock);
    page = find_page(page_boundry);
    if (page != NULL) {
      pthread_mutex_lock(&page->page_lock);
      pthread_mutex_unlock(&change_page_lock);

      // unregister with userfaultfd
      struct uffdio_register uffdio_unregister;
      uffdio_unregister.range.start = page->va;
      uffdio_unregister.range.len = pt_to_pagesize(page->pt);
      // LOG("hemem_mmunmap: unregistering page 0x%lx, size %zu from uffd\n", page->va, pt_to_pagesize(page->pt));
      if (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_unregister) == -1) {
        perror("ioctl uffdio_unregister");
        assert(0);
      }
      // remove page form hemem's and policy's list
      remove_page(page);
      mmgr_remove(page);

      

      mem_allocated -= pt_to_pagesize(page->pt);
      mem_mmaped -= pt_to_pagesize(page->pt);
      pages_freed++;

      // move to next page
      page_boundry += pt_to_pagesize(page->pt);
      pthread_mutex_unlock(&page->page_lock);
    }
    else {
      pthread_mutex_unlock(&change_page_lock);
      // TODO: deal with holes?
      //LOG("hemem_mmunmap: no page to umnap\n");
      //assert(0);
      // printf("hemem_munmap: no page to unmap at addr: %lx\n", page_boundry);
      page_boundry += PAGE_SIZE;
    }
  }


  // ret = libc_munmap(addr, length);

  internal_call--;

  return 0;
}

#ifndef USE_DMA
static void hemem_parallel_memcpy(void *dst, void *src, size_t length)
{
  /* uint64_t i; */
  /* bool all_threads_done; */
  pthread_mutex_lock(&(pmemcpy.lock));
  pmemcpy.dst = dst;
  pmemcpy.src = src;
  pmemcpy.length = length;
  pmemcpy.write_zeros = false;

  int r = pthread_barrier_wait(&pmemcpy.barrier);
  assert(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
  
  //LOG("parallel migration started\n");
  
  /* pmemcpy.activate = true; */

  /* while (!all_threads_done) { */
  /*   all_threads_done = true; */
  /*   for (i = 0; i < MAX_COPY_THREADS; i++) { */
  /*     if (!pmemcpy.done_bitmap[i]) { */
  /*       all_threads_done = false; */
  /*       break; */
  /*     } */
  /*   } */
  /* } */

  r = pthread_barrier_wait(&pmemcpy.barrier);
  assert(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
  //LOG("parallel migration finished\n");
  pthread_mutex_unlock(&(pmemcpy.lock));

  /* pmemcpy.activate = false; */

  /* for (i = 0; i < MAX_COPY_THREADS; i++) { */
  /*   pmemcpy.done_bitmap[i] = false; */
  /* } */
}
#endif

void hemem_migrate_up(struct hemem_page *page, uint64_t dram_offset)
{
  void *old_addr;
  void *new_addr;
  void *newptr;
  struct timeval migrate_start, migrate_end;
  struct timeval start, end;
  uint64_t old_addr_offset, new_addr_offset;
  uint64_t pagesize;
#ifdef USE_DMA
  struct uffdio_dma_copy uffdio_dma_copy;
#endif

  internal_call++;

  assert(!page->in_dram);
  
  gettimeofday(&migrate_start, NULL);
  
  assert(page != NULL);

  pagesize = pt_to_pagesize(page->pt);

  old_addr_offset = page->devdax_offset;
  new_addr_offset = dram_offset;

  old_addr = nvm_devdax_mmap + (old_addr_offset - nvmoffset);
  assert((uint64_t)(old_addr_offset - nvmoffset) < nvmsize);
  assert((uint64_t)(old_addr_offset - nvmoffset) + pagesize <= nvmsize);

  new_addr = dram_devdax_mmap + (new_addr_offset - dramoffset);
  assert((uint64_t)(new_addr_offset - dramoffset) < dramsize);
  assert((uint64_t)(new_addr_offset - dramoffset) + pagesize <= dramsize);

  // copy page from faulting location to temp location
  gettimeofday(&start, NULL);
#ifdef USE_DMA
  uffdio_dma_copy.src[0] = (uint64_t)old_addr;
  uffdio_dma_copy.dst[0] = (uint64_t)new_addr;
  uffdio_dma_copy.len[0] = pagesize;
  uffdio_dma_copy.count = 1;
  uffdio_dma_copy.mode = 0;
  uffdio_dma_copy.copy = 0;
  printf("DMA_COPY: src=%p dst=%p len=%lu\n", old_addr, new_addr, pagesize);

  if (ioctl(uffd, UFFDIO_DMA_COPY, &uffdio_dma_copy) == -1) {
    LOG("hemem_migrate_up, ioctl dma_copy fails for src:%lx, dst:%lx\n", (uint64_t)old_addr, (uint64_t)new_addr); 
    assert(false);
  }
#else
  hemem_parallel_memcpy(new_addr, old_addr, pagesize);
#endif
  gettimeofday(&end, NULL);
  LOG_TIME(MEMCPY_TO_DRAM, elapsed(&start, &end));
 
#ifdef HEMEM_DEBUG 
  uint64_t* src = (uint64_t*)old_addr;
  uint64_t* dst = (uint64_t*)new_addr;
  for (int i = 0; i < (pagesize / sizeof(uint64_t)); i++) {
    if (dst[i] != src[i]) {
      LOG("hemem_migrate_up: dst[%d] = %lu != src[%d] = %lu\n", i, dst[i], i, src[i]);
      assert(dst[i] == src[i]);
    }
  }
#endif

  gettimeofday(&start, NULL);
  assert(libc_mmap != NULL);
  newptr = libc_mmap((void*)page->va, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_FIXED, dramfd, new_addr_offset);
  if (newptr == MAP_FAILED) {
    perror("hemem_migrate_up: newptr mmap");
    assert(0);
  }
  if (newptr != (void*)page->va) {
    fprintf(stderr, "mapped address is not same as faulting address\n");
  }
  assert(page->va % PAGE_SIZE == 0);
  gettimeofday(&end, NULL);
  LOG_TIME(MMAP_DRAM1, elapsed(&start, &end));

  // re-register new mmap region with userfaultfd
  gettimeofday(&start, NULL);
  struct uffdio_register uffdio_register;
  uffdio_register.range.start = (uint64_t)newptr;
  uffdio_register.range.len = pagesize;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
  uffdio_register.ioctls = 0;
  // LOG("hemem_migrate_up: registering page 0x%lx, size %zu with uffd\n", (uint64_t)newptr, pagesize);
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
    // printf("hemem_migrate_up, ioctl fails for uffd: %ld, start: %lx, len: %zu\n", 
    //        uffd, (uint64_t)newptr, pagesize);
    fprintf(stderr, "internal_call=%d\n", internal_call);
    fprintf(stderr, "errno=%d (%s)\n", errno, strerror(errno));
    perror("ioctl uffdio_register");
    assert(0);
  } // Getting error on ioctl. Probably trying to map on the same range twice?
    // Other areas where ioctl is called are: hemem_munmap (unregisters regions), 
    // 
  gettimeofday(&end, NULL);
  LOG_TIME(UFFDIO_REGISTER1, elapsed(&start, &end));

  page->migrations_up++;
  migrations_up++;

  page->devdax_offset = dram_offset;
  page->in_dram = true;
  //page->pa = hemem_va_to_pa(page);

#ifdef ALLOC_LRU
  hemem_tlb_shootdown(page->va);
#endif

  bytes_migrated += pagesize;
  
  //LOG("hemem_migrate_up: new pte: %lx\n", hemem_va_to_pa(page->va));

  gettimeofday(&migrate_end, NULL);  
  LOG_TIME(HEMEM_MIGRATE_UP, elapsed(&migrate_start, &migrate_end));

  internal_call--;
}


void hemem_migrate_down(struct hemem_page *page, uint64_t nvm_offset)
{
  void *old_addr;
  void *new_addr;
  void *newptr;
  struct timeval migrate_start, migrate_end;
  struct timeval start, end;
  uint64_t old_addr_offset, new_addr_offset;
  uint64_t pagesize;
#ifdef USE_DMA
  struct uffdio_dma_copy uffdio_dma_copy;
#endif

  internal_call++;

  assert(page->in_dram);

  //LOG("hemem_migrate_down: migrate down addr: %lx pte: %lx\n", page->va, hemem_va_to_pa(page->va));

  gettimeofday(&migrate_start, NULL);

  pagesize = pt_to_pagesize(page->pt);
  
  assert(page != NULL);
  old_addr_offset = page->devdax_offset;
  new_addr_offset = nvm_offset;

  old_addr = dram_devdax_mmap + (old_addr_offset - dramoffset);
  assert((uint64_t)(old_addr_offset - dramoffset) < dramsize);
  assert((uint64_t)(old_addr_offset - dramoffset) + pagesize <= dramsize);

  new_addr = nvm_devdax_mmap + (new_addr_offset - nvmoffset);
  assert((uint64_t)(new_addr_offset - nvmoffset) < nvmsize);
  assert((uint64_t)(new_addr_offset - nvmoffset) + pagesize <= nvmsize);

  // copy page from faulting location to temp location
  gettimeofday(&start, NULL);
#ifdef USE_DMA
  uffdio_dma_copy.src[0] = (uint64_t)old_addr;
  uffdio_dma_copy.dst[0] = (uint64_t)new_addr;
  uffdio_dma_copy.len[0] = pagesize;
  uffdio_dma_copy.count = 1;
  uffdio_dma_copy.mode = 0;
  uffdio_dma_copy.copy = 0;
  printf("DMA_COPY: src=%p dst=%p len=%lu\n", old_addr, new_addr, pagesize);
  if (ioctl(uffd, UFFDIO_DMA_COPY, &uffdio_dma_copy) == -1) {
    LOG("hemem_migrate_down, ioctl dma_copy fails for src:%lx, dst:%lx\n", (uint64_t)old_addr, (uint64_t)new_addr); 
    assert(false);
  }
#else
  hemem_parallel_memcpy(new_addr, old_addr, pagesize);
#endif
  gettimeofday(&end, NULL);
  LOG_TIME(MEMCPY_TO_NVM, elapsed(&start, &end));

#ifdef HEMEM_DEBUG
  uint64_t* src = (uint64_t*)old_addr;
  uint64_t* dst = (uint64_t*)new_addr;
  for (int i = 0; i < (pagesize / sizeof(uint64_t)); i++) {
    if (dst[i] != src[i]) {
      LOG("hemem_migrate_down: dst[%d] = %lu != src[%d] = %lu\n", i, dst[i], i, src[i]);
      assert(dst[i] == src[i]);
    }
  }
#endif
  
  gettimeofday(&start, NULL);
  newptr = libc_mmap((void*)page->va, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_FIXED, nvmfd, new_addr_offset);
  if (newptr == MAP_FAILED) {
    perror("hemem_migrate_down: newptr mmap");
    assert(0);
  }
  if (newptr != (void*)page->va) {
    fprintf(stderr, "mapped address is not same as faulting address\n");
  }
  assert(page->va % PAGE_SIZE == 0);
  gettimeofday(&end, NULL);
  LOG_TIME(MMAP_NVM1, elapsed(&start, &end));

  // re-register new mmap region with userfaultfd
  gettimeofday(&start, NULL);
  struct uffdio_register uffdio_register;
  uffdio_register.range.start = (uint64_t)newptr;
  uffdio_register.range.len = pagesize;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
  uffdio_register.ioctls = 0;
  // LOG("hemem_migrate_down: registering page 0x%lx, size %zu with uffd\n", (uint64_t)newptr, pagesize);
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
    perror("ioctl uffdio_register");
    assert(0);
  }
  gettimeofday(&end, NULL);
  LOG_TIME(UFFDIO_REGISTER2, elapsed(&start, &end));
  
  page->migrations_down++;
  migrations_down++;

  page->devdax_offset = nvm_offset;
  page->in_dram = false;
  //page->pa = hemem_va_to_pa(page);

#ifdef ALLOC_LRU
  hemem_tlb_shootdown(page->va);
#endif

  bytes_migrated += pagesize;

  //LOG("hemem_migrate_down: new pte: %lx\n", hemem_va_to_pa(page->va));

  gettimeofday(&migrate_end, NULL);  
  LOG_TIME(HEMEM_MIGRATE_DOWN, elapsed(&migrate_start, &migrate_end));

  internal_call--;
}

void hemem_wp_page(struct hemem_page *page, bool protect)
{
  uint64_t addr = page->va;
  struct uffdio_writeprotect wp;
  int ret;
  struct timeval start, end;
  uint64_t pagesize = pt_to_pagesize(page->pt);

  internal_call++;

  //LOG("hemem_wp_page: wp addr %lx pte: %lx\n", addr, hemem_va_to_pa(addr));

  assert(addr != 0);
  assert(addr % PAGE_SIZE == 0);

  gettimeofday(&start, NULL);
  wp.range.start = addr;
  wp.range.len = pagesize;
  wp.mode = (protect ? UFFDIO_WRITEPROTECT_MODE_WP : 0);
  // LOG("hemem_wp_page: %s write protect on page 0x%lx, size %zu\n", (protect ? "enabling" : "disabling"), addr, pagesize);
  ret = ioctl(uffd, UFFDIO_WRITEPROTECT, &wp);

  if (ret < 0) {
    if (!(errno == EBADF || errno == ENOENT)) { 
      perror("uffdio writeprotect");
      assert(0);
    }
  }
  gettimeofday(&end, NULL);

  LOG_TIME(UFFDIO_WRITEPROTECT1, elapsed(&start, &end));

  internal_call--;
}


void handle_wp_fault(uint64_t page_boundry)
{
  struct hemem_page *page;

  internal_call++;

  page = find_page(page_boundry);
  assert(page != NULL);

  migration_waits++;

  LOG("hemem: handle_wp_fault: waiting for migration for page %lx\n", page_boundry);

  while (page->migrating);
  internal_call--;
}


void handle_missing_fault(uint64_t page_boundry)
{
  // Page mising fault case - probably the first touch case
  // allocate in DRAM via LRU
  void* newptr;
  struct timeval missing_start, missing_end;
  struct timeval start, end;
  struct hemem_page *page;
  uint64_t offset;
  void* tmp_offset;
  bool in_dram;
  uint64_t pagesize;

  internal_call++;

  assert(page_boundry != 0);

  /*
  // have we seen this page before?
  page = find_page(page_boundry);
  if (page != NULL) {
    // if yes, must have unmapped it for migration, wait for migration to finish
    LOG("hemem: encountered a page in the middle of migration, waiting\n");
    handle_wp_fault(page_boundry);
    return;
  }
*/
  gettimeofday(&missing_start, NULL);

  gettimeofday(&start, NULL);
  // let policy algorithm do most of the heavy lifting of finding a free page
  page = pagefault();
  assert(page != NULL);
  
  gettimeofday(&end, NULL);
  LOG_TIME(PAGE_FAULT, elapsed(&start, &end));
  
  offset = page->devdax_offset;
  in_dram = page->in_dram;
  pagesize = pt_to_pagesize(page->pt);
  // printf("Page Size: %lu\n", pagesize);

  tmp_offset = (in_dram) ? dram_devdax_mmap + (offset - dramoffset) : nvm_devdax_mmap + (offset - nvmoffset);

#ifdef USE_DMA
#ifdef LLAMA
  memset(tmp_offset, 0, pagesize);
#endif
#else
  hemem_parallel_memset(tmp_offset, 0, pagesize);
#endif
  memsets++;

#ifdef HEMEM_DEBUG
  char* tmp = (char*)tmp_offset;
  for (int i = 0; i < pagesize; i++) {
    assert(tmp[i] == 0);
  }
#endif

  // now that we have an offset determined via the policy algorithm, actually map
  // the page for the application
  gettimeofday(&start, NULL);
  newptr = libc_mmap((void*)page_boundry, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_FIXED, (in_dram ? dramfd : nvmfd), offset);
  if (newptr == MAP_FAILED) {
    perror("handle_missing_fault: newptr mmap");
    /* free(page); */
    assert(0);
  }
  LOG("hemem: mmaping at %p\n", newptr);
  if(newptr != (void *)page_boundry) {
    fprintf(stderr, "Not mapped where expected (%p != %p)\n", newptr, (void *)page_boundry);
    assert(0);
  }
  gettimeofday(&end, NULL);
  if (in_dram) {
    LOG_TIME(MMAP_DRAM, elapsed(&start, &end));
  } else {
    LOG_TIME(MMAP_NVM, elapsed(&start, &end));
  }

  gettimeofday(&start, NULL);
  // re-register new mmap region with userfaultfd
  struct uffdio_register uffdio_register;
  uffdio_register.range.start = (uint64_t)newptr;
  uffdio_register.range.len = pagesize;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
  uffdio_register.ioctls = 0;
  // LOG("handle_missing_fault: registering page 0x%lx, size %zu with uffd\n", (uint64_t)newptr, pagesize);
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
    perror("ioctl uffdio_register");
    printf("in handle_missing_fault: addr: %p, length: %zu\n", newptr, pagesize);
    assert(0);
  }
  gettimeofday(&end, NULL);
  LOG_TIME(UFFDIO_REGISTER3, elapsed(&start, &end));

  // use mmap return addr to track new page's virtual address
  page->va = (uint64_t)newptr;
  assert(page->va != 0);
  assert(page->va % PAGE_SIZE == 0);
  page->migrating = false;
  page->migrations_up = page->migrations_down = 0;
  struct timeval null_mig = {0};
  page->mig_start = null_mig;
  //page->pa = hemem_va_to_pa(page);
 
  pages_allocated++;
  mem_allocated += pagesize;

  //LOG("hemem_missing_fault: va: %lx assigned to %s frame %lu  pte: %lx\n", page->va, (in_dram ? "DRAM" : "NVM"), page->devdax_offset / pagesize, hemem_va_to_pa(page->va));

  // place in hemem's page tracking list
  add_page(page);

  missing_faults_handled++;
  gettimeofday(&missing_end, NULL);
  LOG_TIME(HEMEM_MISSING_FAULT, elapsed(&missing_start, &missing_end));
  internal_call--;
  pthread_mutex_unlock(&page->page_lock);
}



void *handle_fault()
{
  static struct uffd_msg msg[MAX_UFFD_MSGS];
  ssize_t nread;
  uint64_t fault_addr;
  uint64_t fault_flags;
  uint64_t page_boundry;
  struct uffdio_range range;
  int ret;
  int nmsgs;
  int i;

  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(FAULT_THREAD_CPU_DEFAULT, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for (;;) {
    struct pollfd pollfd;
    int pollres;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    pollres = poll(&pollfd, 1, -1);

    switch (pollres) {
    case -1:
      perror("poll");
      assert(0);
    case 0:
      fprintf(stderr, "poll read 0\n");
      continue;
    case 1:
      break;
    default:
      fprintf(stderr, "unexpected poll result\n");
      assert(0);
    }

    if (pollfd.revents & POLLERR) {
      fprintf(stderr, "pollerr\n");
      assert(0);
    }

    if (!pollfd.revents & POLLIN) {
      continue;
    }

    nread = read(uffd, &msg[0], MAX_UFFD_MSGS * sizeof(struct uffd_msg));
    if (nread == 0) {
      fprintf(stderr, "EOF on userfaultfd\n");
      assert(0);
    }

    if (nread < 0) {
      if (errno == EAGAIN) {
        continue;
      }
      perror("read");
      assert(0);
    }

    if ((nread % sizeof(struct uffd_msg)) != 0) {
      fprintf(stderr, "invalid msg size: [%ld]\n", nread);
      assert(0);
    }

    nmsgs = nread / sizeof(struct uffd_msg);

    for (i = 0; i < nmsgs; i++) {
      //TODO: check page fault event, handle it
      if (msg[i].event & UFFD_EVENT_PAGEFAULT) {
        fault_addr = (uint64_t)msg[i].arg.pagefault.address;
        fault_flags = msg[i].arg.pagefault.flags;

        // allign faulting address to page boundry
        // huge page boundry in this case due to dax allignment
        page_boundry = fault_addr & ~(PAGE_SIZE - 1);

        if (fault_flags & UFFD_PAGEFAULT_FLAG_WP) {
          handle_wp_fault(page_boundry);
        }
        else {
          handle_missing_fault(page_boundry);
        }

        // wake the faulting thread
        range.start = (uint64_t)page_boundry;
        range.len = PAGE_SIZE;
        // LOG("uffdio_wake: waking page 0x%lx, size %zu\n", range.start, range.len);
        ret = ioctl(uffd, UFFDIO_WAKE, &range);

        if (ret < 0) {
          perror("uffdio wake");
          assert(0);
        }
      }
      else if (msg[i].event & UFFD_EVENT_UNMAP){
        fprintf(stderr, "Received an unmap event\n");
        assert(0);
      }
      else if (msg[i].event & UFFD_EVENT_REMOVE) {
        fprintf(stderr, "received a remove event\n");
        assert(0);
      }
      else {
        fprintf(stderr, "received a non page fault event\n");
        assert(0);
      }
    }
  }
}

#ifdef ALLOC_LRU
void hemem_tlb_shootdown(uint64_t va)
{
  uint64_t page_boundry = va & ~(PAGE_SIZE - 1);
  struct uffdio_range range;
  int ret;
  
  range.start = page_boundry;
  range.len = PAGE_SIZE;
  // LOG("hemem_tlb_shootdown: shooting down TLB for page 0x%lx, size %zu\n", range.start, range.len);
  ret = ioctl(uffd, UFFDIO_TLBFLUSH, &range);
  if (ret < 0) {
    perror("uffdio tlbflush");
    assert(0);
  }
}
#endif

#ifdef ALLOC_LRU
void hemem_clear_bits(struct hemem_page *page)
{
  uint64_t ret;
  struct uffdio_page_flags page_flags;

  page_flags.va = page->va;
  assert(page_flags.va % PAGE_SIZE == 0);
  page_flags.flag1 = HEMEM_ACCESSED_FLAG;
  page_flags.flag2 = HEMEM_DIRTY_FLAG;
  // LOG("hemem_clear_bits: clearing accessed and dirty bits for page 0x%lx\n", page->va);
  if (ioctl(uffd, UFFDIO_CLEAR_FLAG, &page_flags) < 0) {
    fprintf(stderr, "userfaultfd_clear_flag returned < 0\n");
    assert(0);
  }

  ret = page_flags.res1;
  if (ret == 0) {
    LOG("hemem_clear_accessed_bit: accessed bit not cleared\n");
  }
}
#endif

#ifdef ALLOC_LRU
uint64_t hemem_get_bits(struct hemem_page *page)
{
  uint64_t ret;
  struct uffdio_page_flags page_flags;

  page_flags.va = page->va;
  assert(page_flags.va % PAGE_SIZE == 0);
  page_flags.flag1 = HEMEM_ACCESSED_FLAG;
  page_flags.flag2 = HEMEM_DIRTY_FLAG;
  // LOG("hemem_get_bits: getting accessed and dirty bits for page 0x%lx\n", page->va);
  if (ioctl(uffd, UFFDIO_GET_FLAG, &page_flags) < 0) {
    fprintf(stderr, "userfaultfd_get_flag returned < 0\n");
    assert(0);
  }

  ret = page_flags.res1 | page_flags.res2;

  return ret;;
}
#endif

void hemem_print_stats(FILE *fd)
{

  LOG_STATS("pid: [%u]\tmem_allocated: [%lu]\tpages_allocated: [%lu]\tmissing_faults_handled: [%lu]\tbytes_migrated: [%lu]\tmigrations_up: [%lu]\tmigrations_down: [%lu]\tmigration_waits: [%lu]\n", 
               getpid(),
               mem_allocated, 
               pages_allocated, 
               missing_faults_handled, 
               bytes_migrated,
               migrations_up, 
               migrations_down,
               migration_waits);
  fprintf(miss_ratio_f, "pid: [%u]\ttmigrations_up: %lu\ttmigrations_down: %lu\ttotal_migrations: %lu\t", 
               getpid(),
               migrations_up, 
               migrations_down,
               migrations_up + migrations_down);
   mmgr_stats(); 
}

void hemem_clear_stats()
{
  pages_allocated = 0;
  pages_freed = 0;
  missing_faults_handled = 0;
  migrations_up = 0;
  migrations_down = 0;
}

void hemem_clear_stats_full()
{
  migration_waits = 0;
  bytes_migrated = 0;
  hemem_clear_stats();
}


struct hemem_page* get_hemem_page(uint64_t va)
{
  return find_page(va);
}

void hemem_start_timing(void)
{
  timing = true;
}

void hemem_stop_timing(void)
{
  timing = false;
}
