#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <errno.h>
#define __USE_GNU
#include <dlfcn.h>
#include <pthread.h>
#include <sys/mman.h>
#include <assert.h>
#include <malloc.h>

#include <unistd.h>

#include "hemem.h"
#include "interpose.h"

void* (*libc_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;
int (*libc_munmap)(void *addr, size_t length) = NULL;


static int mmap_filter(void *addr, size_t length, int prot, int flags, int fd, off_t offset, uint64_t *result)
{
  if (fd == dramfd || fd == nvmfd) {
    // devdax mappings should go to libc
    LOG("hemem interpose: calling libc mmap due to devdax mapping: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }
  // if (length == 2147487744) {
  //   LOG("hemem interpose: hooked main malloc: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
  // }
  //ensure_init();

  assert(internal_call >= 0);
  if (internal_call) {
    // printf("internal_call: %d\n", internal_call);
    LOG("hemem interpose: calling libc mmap due to internal memory call: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }

  if (getpid() != main_thread) {
    // only the main thread should be making mmap calls
    LOG("hemem interpose: calling libc mmap due to non-main thread memory call: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }

  pid_t tid = gettid();
  // pthread_mutex_lock(&internal_thread_lock);
  for (uint32_t i = 0; i < num_internal_threads; i++) {
    if (tid == internal_threads[i]) {
      LOG("hemem interpose: calling libc munmap due to internal thread call: munmap(0x%lx, %ld)\n", (uint64_t)addr, length);
      // pthread_mutex_unlock(&internal_thread_lock);
      return 1;
    }
  }
  // pthread_mutex_unlock(&internal_thread_lock);

  //TODO: figure out which mmap calls should go to libc vs hemem
  // non-anonymous mappings should probably go to libc (e.g., file mappings)
  if (((flags & MAP_ANONYMOUS) != MAP_ANONYMOUS) && !((fd == dramfd) || (fd == nvmfd))) {
    LOG("hemem interpose: calling libc mmap due to non-anonymous, non-devdax mapping: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }
  
  if ((prot & PROT_EXEC) == PROT_EXEC) {
    // filter out code mappings
    LOG("hemem interpose: calling libc mmap due to code mapping: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }

  if ((flags & MAP_STACK) == MAP_STACK) {
    // pthread mmaps are called with MAP_STACK
    LOG("hemem interpose: calling libc mmap due to stack mapping: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }

  //if (((flags & MAP_NORESERVE) == MAP_NORESERVE)) {
    // thread stack is called without swap space reserved, so we can probably ignore these
    //fprintf(stderr, "hemem interpose: calling libc mmap due to non-swap space reserved mapping: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    //return 1;
  //}
  if ((prot & PROT_READ) != PROT_READ || (prot & PROT_WRITE) != PROT_WRITE) {
    // read-only mappings are probably code or file mappings
    LOG("hemem interpose: calling libc mmap due to read-only mapping: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }
  
  if ((fd == dramfd) || (fd == nvmfd)) {
    LOG("hemem interpose: calling libc mmap due to hemem devdax mapping: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }

  if (fd != -1) {
    // file mappings should go to libc
    LOG("hemem interpose: calling libc mmap due to file mapping: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }

// #ifndef LLAMA
  if (length <= 2UL * 1024UL * 1024UL) {
    LOG("hemem interpose calling libc mmap due to small allocation size: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }
// #endif
  if ((uint64_t)addr % PAGE_SIZE != 0) {
    LOG("hemem interpose calling libc mmap due to unaligned address: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
    return 1;
  }
  // printf("hemem interpose: using hemem mmap: mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);

  LOG("hemem interpose: calling hemem mmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
  if ((*result = (uint64_t)hemem_mmap(addr, length, prot, flags, fd, offset)) == (uint64_t)MAP_FAILED) {
    // hemem failed for some reason, try libc
    LOG("hemem mmap failed\n\tmmap(0x%lx, %ld, %x, %x, %d, %ld)\n", (uint64_t)addr, length, prot, flags, fd, offset);
  }
  return 0;
}

// Currently, this iterates over the entire region page by page unmapping any hemem pages it finds.
// Then it returns that it failed so libc_munmap is called to unmap the entire region.
// This is very inefficient if the munmap is for a non-hemem region. But assuming most large regions are
// tracked by hemem, it should be fine.
static int munmap_filter(void *addr, size_t length, uint64_t* result)
{
  // Getting a 'free(): invalid pointer' error which is probably from this function
  // Need to figure out how to tell when to use libc munmap vs hemem munmap
  //ensure_init();
  
  //TODO: figure out which munmap calls should go to libc vs hemem

  // Need to not use a lock because possible race condition sequence:
  // All on same thread: mmap called in application -> interpose mmap_filter -> hemem_mmap -> hemem_mmap_populate -> 
  // add_page -> pthread_mutex_lock(&pages_lock) -> interrupt for munmap -> munmap_filter -> find_page -> pthread_mutex_lock(&pages_lock) -> deadlock on pages_lock
  // struct hemem_page *page = find_page((uint64_t)addr);
  // if (page == NULL) {
  //   // not a hemem-managed page, use libc munmap
  //   LOG("hemem interpose: calling libc munmap due to non-hemem page: munmap(0x%lx, %ld)\n", (uint64_t)addr, length);
  //   return 1;
  // }
  if (getpid() != main_thread) {
    // only the main process should make allocations
    LOG("hemem interpose: calling libc munmap due to non-main process memory call: munmap(0x%lx, %ld)\n", (uint64_t)addr, length);
    return 1;
  }
  pid_t tid = gettid();
  // pthread_mutex_lock(&internal_thread_lock);
  for (uint32_t i = 0; i < num_internal_threads; i++) {
    if (tid == internal_threads[i]) {
      LOG("hemem interpose: calling libc munmap due to internal thread call: munmap(0x%lx, %ld)\n", (uint64_t)addr, length);
      // pthread_mutex_unlock(&internal_thread_lock);
      return 1;
    }
  }
  // pthread_mutex_unlock(&internal_thread_lock);

  // if (internal_call) {
  //   // printf("internal_call: %d\n", internal_call);
  //   LOG("hemem interpose: calling libc munmap due to internal memory call: munmap(0x%lx, %ld)\n", (uint64_t)addr, length);
  //   return 1;
  // }
  
  // Try to do hemem_munmap across the entire range. If it doesn't find a page at the address it skips it.
  // Then return 1 to call libc_munmap anyway to free the page since it already did that before
  LOG("hemem interpose: calling hemem munmap(0x%lx, %ld)\n", (uint64_t)addr, length)
  if ((*result = hemem_munmap(addr, length)) == -1) {
    LOG("hemem munmap failed\n\tmunmap(0x%lx, %ld)\n", (uint64_t)addr, length);
  }
  return 1;
}


static void* bind_symbol(const char *sym)
{
  void *ptr;
  if ((ptr = dlsym(RTLD_NEXT, sym)) == NULL) {
    fprintf(stderr, "hemem memory manager interpose: dlsym failed (%s)\n", sym);
    abort();
  }
  return ptr;
}

// hooks mmap and munmap syscalls
static int hook(long syscall_number, long arg0, long arg1, long arg2, long arg3,	long arg4, long arg5,	long *result)
{
	if (syscall_number == SYS_mmap) {
	  return mmap_filter((void*)arg0, (size_t)arg1, (int)arg2, (int)arg3, (int)arg4, (off_t)arg5, (uint64_t*)result);
	} else if (syscall_number == SYS_munmap){
    return munmap_filter((void*)arg0, (size_t)arg1, (uint64_t*)result);
  } else {
    // ignore non-mmap system calls
		return 1;
	}
}

static __attribute__((constructor)) void init(void)
{
  libc_mmap = bind_symbol("mmap");
  libc_munmap = bind_symbol("munmap");
  intercept_hook_point = hook;

  // set threshold to 0 so all allocations go to mmap and get hooked
  int ret = mallopt(M_MMAP_THRESHOLD, 0);
  
  if (ret != 1) {
    perror("mallopt");
  }
  assert(ret == 1);

  // increase the max number of mmaps because hemem breaks up mmaps into multiple mmaps of PAGE_SIZE
  ret = mallopt(M_MMAP_MAX, 4194304);
  if (ret != 1) {
    perror("mallopt");
  }
  assert(ret == 1);
  
  hemem_init();
}

static __attribute__((destructor)) void hemem_shutdown(void)
{
  hemem_stop();
}
