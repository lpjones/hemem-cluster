#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <math.h>
#include <errno.h>

#include "hemem.h"
#include "pebs.h"
#include "timer.h"
#include "spsc-ring.h"

struct pebs_record {
    uint64_t tsc;
    uint64_t va;
    uint64_t ip;
    uint32_t cpu;
    uint8_t  event;

} __attribute__((packed));

struct running_stats {
    uint64_t count;
    double mean;
    double M2;
};

struct mean_var {
  double mean;
  double var;
};

struct pebs_rec_stats {
  struct running_stats tsc_stats;
  struct running_stats va_stats;
  struct running_stats ip_stats;
};

struct pebs_rec_stats running_stats = {0};

void update_stats(struct running_stats *stats, double new_value)
{
  stats->count++;
  double delta = new_value - stats->mean;
  stats->mean += delta / stats->count;
  double delta2 = new_value - stats->mean;
  stats->M2 += delta * delta2;
}

struct mean_var get_stats(struct running_stats *stats)
{
  if (stats->count < 2) {
    return (struct mean_var){-1, -1};  // Not enough data
  }
  double mean = stats->mean;
  double sample_variance = stats->M2 / (stats->count - 1);
  return (struct mean_var){mean, sample_variance};
}

#define MAX_PAGES ((DRAMSIZE_DEFAULT + NVMSIZE_DEFAULT + PAGE_SIZE - 1) / (PAGE_SIZE))
struct pebs_record page_records[MAX_PAGES];

uint64_t rec_hash(uint64_t va)
{
  return (va >> LOG_PAGE_SIZE) % (MAX_PAGES);
}

void add_or_update_record(uint64_t tsc, uint64_t va, uint64_t ip, uint32_t cpu, uint8_t event)
{
  uint64_t hash = rec_hash(va);
  uint64_t old_hash = hash;
  while (page_records[hash].va != va && page_records[hash].va != 0) {
    // linear probe for collisions
    hash = (hash + 1) % MAX_PAGES;
    assert(old_hash != hash);
  }
  update_stats(&running_stats.tsc_stats, tsc);
  update_stats(&running_stats.va_stats, va);
  update_stats(&running_stats.ip_stats, ip);
  // printf("Add/Update: %lu, 0x%lx, 0x%lx, %d, %d\n", tsc, va, ip, cpu, event);
  page_records[hash].tsc = tsc;
  page_records[hash].va = va;
  page_records[hash].ip = ip;
  page_records[hash].cpu = cpu;
  page_records[hash].event = event;
}

struct pebs_record *find_record(uint64_t va)
{
  uint64_t hash = rec_hash(va);
  while (page_records[hash].va != 0) {
    if (page_records[hash].va == va) {
      return &page_records[hash];
    }
    hash = (hash + 1) % MAX_PAGES;
  }
  return NULL;
}



uint64_t pebs_start_cpu;
uint64_t migration_thread_cpu;
uint64_t scanning_thread_cpu;

static struct fifo_list dram_hot_list;
static struct fifo_list dram_cold_list;
static struct fifo_list nvm_hot_list;
static struct fifo_list nvm_cold_list;
static struct fifo_list dram_free_list;
static struct fifo_list nvm_free_list;
static ring_handle_t hot_ring;
static ring_handle_t cold_ring;
static ring_handle_t free_page_ring;
static pthread_mutex_t free_page_ring_lock = PTHREAD_MUTEX_INITIALIZER;
uint64_t global_clock = 0;

uint64_t hemem_pages_cnt = 0;
uint64_t other_pages_cnt = 0;
_Atomic uint64_t total_pages_cnt = 0;
uint64_t accesses_cnt[NPBUFTYPES];
uint64_t core_accesses_cnt[PEBS_NPROCS];
_Atomic uint64_t zero_pages_cnt = 0;
_Atomic uint64_t throttle_cnt = 0;
_Atomic uint64_t unthrottle_cnt = 0;
uint64_t cools = 0;

_Atomic volatile double miss_ratio = -1.0;
FILE *miss_ratio_f = NULL;
bool _Atomic miss_ratio_f_opened = false;

static struct perf_event_mmap_page *perf_page[PEBS_NPROCS][NPBUFTYPES];
int pfd[PEBS_NPROCS][NPBUFTYPES];

volatile bool need_cool_dram = false;
volatile bool need_cool_nvm = false;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, 
    int cpu, int group_fd, unsigned long flags)
{
  int ret;

  ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		group_fd, flags);
  return ret;
}

static struct perf_event_mmap_page* perf_setup(__u64 config, __u64 config1, __u64 cpu, __u64 type)
{
  struct perf_event_attr attr;

  memset(&attr, 0, sizeof(struct perf_event_attr));

  attr.type = PERF_TYPE_RAW;
  attr.size = sizeof(struct perf_event_attr);

  attr.config = config;
  attr.config1 = config1;
  attr.sample_period = SAMPLE_PERIOD;

  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_WEIGHT | PERF_SAMPLE_ADDR;
  attr.disabled = 0;
  //attr.inherit = 1;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.exclude_callchain_kernel = 1;
  attr.exclude_callchain_user = 1;
  attr.precise_ip = 1;

  pfd[cpu][type] = perf_event_open(&attr, -1, cpu, -1, 0);
  if(pfd[cpu][type] == -1) {
    perror("perf_event_open");
  }
  assert(pfd[cpu][type] != -1);

  fprintf(stderr, "Set up perf on core %llu\n", cpu);
  size_t mmap_size = sysconf(_SC_PAGESIZE) * PERF_PAGES;
  /* printf("mmap_size = %zu\n", mmap_size); */
  struct perf_event_mmap_page *p = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, pfd[cpu][type], 0);
  if(p == MAP_FAILED) {
    perror("mmap");
  }
  assert(p != MAP_FAILED);

  return p;
}

void make_hot_request(struct hemem_page* page)
{
  gettimeofday(&page->mig_start, NULL);
  page->ring_present = true;
  ring_buf_put(hot_ring, (uint64_t*)page); 
}

void make_cold_request(struct hemem_page* page)
{
  gettimeofday(&page->mig_start, NULL);
  page->ring_present = true;
  ring_buf_put(cold_ring, (uint64_t*)page);
}

void cluster_stride(struct hemem_page *page)
{
  // hot
  uint64_t predicted_va = page->va + 10 * PAGE_SIZE;
  __u64 predicted_pfn = predicted_va & PAGE_PFN_MASK;
  struct hemem_page *predicted_page = get_hemem_page(predicted_pfn);
  if (predicted_page != NULL && predicted_page->va != 0) {
    if (!predicted_page->hot && !predicted_page->ring_present) {
      make_hot_request(predicted_page);
    }
  }

  // cold
  predicted_va = page->va - PAGE_SIZE;
  predicted_pfn = predicted_va & PAGE_PFN_MASK;
  predicted_page = get_hemem_page(predicted_pfn);
  if (predicted_page != NULL && predicted_page->va != 0) {
    if (predicted_page->hot && !predicted_page->ring_present) {
      make_cold_request(predicted_page);
    }
  }
}

double cluster_distance(struct pebs_record *a, struct pebs_record *b)
{
  struct mean_var tsc_stats = get_stats(&running_stats.tsc_stats);
  struct mean_var va_stats = get_stats(&running_stats.va_stats);
  struct mean_var ip_stats = get_stats(&running_stats.ip_stats);

  // Compute the distance between two records
  double va_dist = (((double)a->va - (double)b->va) - va_stats.mean) / va_stats.var;
  double ip_dist = (((double)a->ip - (double)b->ip) - ip_stats.mean) / ip_stats.var;
  double tsc_dist = (((double)a->tsc - (double)b->tsc) - tsc_stats.mean) / tsc_stats.var;

  return sqrt(va_dist * va_dist + ip_dist * ip_dist + tsc_dist * tsc_dist);
}

void cluster_cluster(struct hemem_page *page, bool is_hot)
{
  // find pages close in "distance"
  double threshold = 0.01;
  struct pebs_record *main_page = find_record(page->va);
  assert(main_page != NULL);

  for (uint32_t i = 0; i < MAX_PAGES; i++) {
    double dist = cluster_distance(main_page, &page_records[i]);
    if (dist < threshold) {
      // Found a close page
      struct hemem_page *cur_page = get_hemem_page(page_records[i].va);
      if (cur_page != NULL && cur_page->va != 0) {
        // Do something with cur_page
        if (is_hot) {
          if (!page->hot && !page->ring_present) {
            // printf("Making Hot request: 0x%lx\n", cur_page->va);
            make_hot_request(cur_page);
          }
        } else {
          if (page->hot && !page->ring_present) {
            // printf("Making Cold request: 0x%lx\n", cur_page->va);
            make_cold_request(cur_page);
          }
        }
      }
    }
  }

}

void *pebs_scan_thread()
{
#ifdef SAMPLE_BASED_COOLING
  uint64_t samples_since_cool = 0;
#endif

  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  scanning_thread_cpu = 0;
  CPU_SET(scanning_thread_cpu, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for(;;) {
    for (int i = pebs_start_cpu; i < pebs_start_cpu + num_cores; i++) {
      for(int j = 0; j < NPBUFTYPES; j++) {
        struct perf_event_mmap_page *p = perf_page[i][j];
        char *pbuf = (char *)p + p->data_offset;

        __sync_synchronize();

        if(p->data_head == p->data_tail) {
          continue;
        }

        struct perf_event_header *ph = (void *)(pbuf + (p->data_tail % p->data_size));
        struct perf_sample* ps;
        struct hemem_page* page;

        switch(ph->type) {
        case PERF_RECORD_SAMPLE:
            ps = (struct perf_sample*)ph;
            assert(ps != NULL);
            if(ps->addr != 0) {
              __u64 pfn = ps->addr & PAGE_PFN_MASK;
              assert(pfn % PAGE_SIZE == 0);
              // printf("PEBS sample: 0x%llx\n", pfn);
              // print all HeMem pages
              
            
              page = get_hemem_page(pfn);
              if (page != NULL) {
                if (page->va != 0) {
                  // printf("hemem sample: 0x%lx\n", page->va);
                  page->accesses[j]++;
                  page->tot_accesses[j]++;
                  // add_or_update_record(rdtscp(), page->va, ps->ip, i, j);
                  
                  // cluster_cluster()
                  // cluster_stride(page);
                  //if (page->accesses[WRITE] >= HOT_WRITE_THRESHOLD) {
                  //  if (!page->hot && !page->ring_present) {
                  //      make_hot_request(page);
                  //  }
                  //}
                  /*else*/ if (page->accesses[DRAMREAD] + page->accesses[NVMREAD] >= HOT_READ_THRESHOLD) {
                    if (!page->hot && !page->ring_present) {
                        make_hot_request(page);
                        // cluster_cluster(page, true);
                    }
                  }
                  else if (/*(page->accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (page->accesses[DRAMREAD] + page->accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
                    if (page->hot && !page->ring_present) {
                        make_cold_request(page);
                        // cluster_cluster(page, false);
                    }
                 }

                  accesses_cnt[j]++;
                  core_accesses_cnt[i]++;

                  page->accesses[DRAMREAD] >>= (global_clock - page->local_clock);
                  page->accesses[NVMREAD] >>= (global_clock - page->local_clock);
                  //page->accesses[WRITE] >>= (global_clock - page->local_clock);
                  page->local_clock = global_clock;
                  #ifndef SAMPLE_BASED_COOLING
                  if (page->accesses[j] > PEBS_COOLING_THRESHOLD) {
                    global_clock++;
                    cools++;
                    need_cool_dram = true;
                    need_cool_nvm = true;
                  }
                  #else
                  if (samples_since_cool > SAMPLE_COOLING_THRESHOLD) {
                    global_clock++;
                    cools++;
                    need_cool_dram = true;
                    need_cool_nvm = true;
                    samples_since_cool = 0;
                  }
                  #endif
                }
                #ifdef SAMPLE_BASED_COOLING
                samples_since_cool++;
                #endif
                hemem_pages_cnt++;
              }
              else {
                other_pages_cnt++;
              }
            
              total_pages_cnt++;
            }
            else {
              zero_pages_cnt++;
            }
  	      break;
        case PERF_RECORD_THROTTLE:
        case PERF_RECORD_UNTHROTTLE:
          //fprintf(stderr, "%s event!\n",
          //   ph->type == PERF_RECORD_THROTTLE ? "THROTTLE" : "UNTHROTTLE");
          if (ph->type == PERF_RECORD_THROTTLE) {
              throttle_cnt++;
          }
          else {
              unthrottle_cnt++;
          }
          break;
        default:
          // fprintf(stderr, "Unknown type %u\n", ph->type);
          //assert(!"NYI");
          break;
        }

        p->data_tail += ph->size;
      }
    }
  }

  return NULL;
}

static void pebs_migrate_down(struct hemem_page *page, uint64_t offset)
{
  struct timeval start, end;

  gettimeofday(&start, NULL);
  if (page->mig_start.tv_sec != 0)
    LOG_TIME(MIG_QUEUE_DELAY_DOWN, elapsed(&page->mig_start, &start));

  page->migrating = true;
  hemem_wp_page(page, true);
  hemem_migrate_down(page, offset);
  page->migrating = false; 

  gettimeofday(&end, NULL);
  LOG_TIME(MIGRATE_DOWN, elapsed(&start, &end));

}

static void pebs_migrate_up(struct hemem_page *page, uint64_t offset)
{
  struct timeval start, end;

  gettimeofday(&start, NULL);
  if (page->mig_start.tv_sec != 0)
    LOG_TIME(MIG_QUEUE_DELAY_UP, elapsed(&page->mig_start, &start));

  page->migrating = true;
  hemem_wp_page(page, true);
  // printf("calling hemem_migrate_up from pebs_migrate_up for page %lx to dram offset %lx\n", page->va, offset);
  hemem_migrate_up(page, offset);
  page->migrating = false;

  gettimeofday(&end, NULL);
  LOG_TIME(MIGRATE_UP, elapsed(&start, &end));

}

// moves page to hot list -- called by migrate thread
// Only in pebs_policy_thread
void make_hot(struct hemem_page* page)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (page->hot) {
    if (page->in_dram) {
      assert(page->list == &dram_hot_list);
    }
    else {
      assert(page->list == &nvm_hot_list);
    }
    return;
  }

  if (page->in_dram && page->list == &dram_cold_list) {
    // assert(page->list == &dram_cold_list);
    page_list_remove_page(&dram_cold_list, page);
    page->hot = true;
    enqueue_fifo(&dram_hot_list, page);
  }
  else if (!page->in_dram && page->list == &nvm_cold_list) {
    // assert(page->list == &nvm_cold_list);
    page_list_remove_page(&nvm_cold_list, page);
    page->hot = true;
    enqueue_fifo(&nvm_hot_list, page);
  }
}

// moves page to cold list -- called by migrate thread
// Only in pebs_policy_thread
void make_cold(struct hemem_page* page)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (!page->hot) {
    if (page->in_dram) {
      assert(page->list == &dram_cold_list);
    }
    else {
      assert(page->list == &nvm_cold_list);
    }
    return;
  }

  if (page->in_dram && page->list == &dram_hot_list) {
    // assert(page->list == &dram_hot_list);
    page_list_remove_page(&dram_hot_list, page);
    page->hot = false;
    enqueue_fifo(&dram_cold_list, page);
  }
  else if (!page->in_dram && page->list == &nvm_hot_list) {
    // assert(page->list == &nvm_hot_list);
    page_list_remove_page(&nvm_hot_list, page);
    page->hot = false;
    enqueue_fifo(&nvm_cold_list, page);
  }
}

static struct hemem_page* start_dram_page = NULL;
static struct hemem_page* start_nvm_page = NULL;

#ifdef COOL_IN_PLACE
// Only in pebs_policy_thread
struct hemem_page* partial_cool(struct fifo_list *hot, struct fifo_list *cold, bool dram, struct hemem_page* current)
{
  struct hemem_page *p;
  uint64_t tmp_accesses[NPBUFTYPES];

  if (dram && !need_cool_dram) {
      return current;
  }
  if (!dram && !need_cool_nvm) {
      return current;
  }

  if (start_dram_page == NULL && dram) {
      start_dram_page = hot->last;
  }

  if (start_nvm_page == NULL && !dram) {
      start_nvm_page = hot->last;
  }

  for (int i = 0; i < COOLING_PAGES; i++) {
    next_page(hot, current, &p);
    if (p == NULL) {
        break;
    }
    if (dram) {
        assert(p->in_dram);
    }
    else {
        assert(!p->in_dram);
    }

    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }

    if (/*(tmp_accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
        p->hot = false;
    }
    
    if (dram && (p == start_dram_page)) {
        start_dram_page = NULL;
        need_cool_dram = false;
    }

    if (!dram && (p == start_nvm_page)) {
        start_nvm_page = NULL;
        need_cool_nvm = false;
    } 

    if (!p->hot) {
        current = p->next;
        page_list_remove_page(hot, p);
        enqueue_fifo(cold, p);
    }
    else {
        current = p;
    }
  }

  return current;
}
#else
// Only in pebs_policy_thread (Not enabled with COOL_IN_PLACE)
static void partial_cool(struct fifo_list *hot, struct fifo_list *cold, bool dram)
{
  struct hemem_page *p;
  uint64_t tmp_accesses[NPBUFTYPES];

  if (dram && !need_cool_dram) {
      return;
  }
  if (!dram && !need_cool_nvm) {
      return;
  }

  if ((start_dram_page == NULL) && dram) {
      start_dram_page = hot->last;
  }

  if ((start_nvm_page == NULL) && !dram) {
      start_nvm_page = hot->last;
  }

  for (int i = 0; i < COOLING_PAGES; i++) {
    pthread_mutex_lock(&change_page_lock);
    p = dequeue_fifo(hot);
    if (p == NULL) {
        pthread_mutex_unlock(&change_page_lock);
        break;
    }
    pthread_mutex_lock(&p->page_lock);
    pthread_mutex_unlock(&change_page_lock);
    if (dram) {
        assert(p->in_dram);
    }
    else {
        assert(!p->in_dram);
    }

    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }

    if (/*(tmp_accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
        p->hot = false;
    }

    if (dram && (p == start_dram_page)) {
        start_dram_page = NULL;
        need_cool_dram = false;
    }

    if (!dram && (p == start_nvm_page)) {
        start_nvm_page = NULL;
        need_cool_nvm = false;
    } 

    if (p->hot) {
      enqueue_fifo(hot, p);
    }
    else {
      enqueue_fifo(cold, p);
    }
    pthread_mutex_unlock(&p->page_lock);
  }
}
#endif

#ifdef COOL_IN_PLACE
// Only in pebs_policy_thread
void update_current_cool_page(struct hemem_page** cur_cool_in_dram, struct hemem_page** cur_cool_in_nvm, struct hemem_page* page)
{
    if (page == NULL) {
        return;
    }

    if (page == *cur_cool_in_dram) {
        assert(page->list == &dram_hot_list);
        next_page(page->list, page, cur_cool_in_dram);
    }
    if (page == *cur_cool_in_nvm) {
        assert(page->list == &nvm_hot_list);
        next_page(page->list, page, cur_cool_in_nvm);
    }
}
#endif

void *pebs_policy_thread()
{
  cpu_set_t cpuset;
  pthread_t thread;
  struct timeval start, end;
  int tries;
  struct hemem_page *p;
  struct hemem_page *cp;
  struct hemem_page *np;
  uint64_t migrated_bytes;
  uint64_t old_offset;
  int num_ring_reqs;
  struct hemem_page* page = NULL;
  double migrate_time;
  #ifdef COOL_IN_PLACE
  struct hemem_page* cur_cool_in_dram  = NULL;
  struct hemem_page* cur_cool_in_nvm = NULL;
  #endif

  migration_thread_cpu = 2;
  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(migration_thread_cpu, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for (;;) {
    gettimeofday(&start, NULL);
    // free pages using free page ring buffer
    while(!ring_buf_empty(free_page_ring)) {
        struct fifo_list *list;
        pthread_mutex_lock(&change_page_lock);
        page = (struct hemem_page*)ring_buf_get(free_page_ring);
        if (page == NULL || page->list == NULL) {
            pthread_mutex_unlock(&change_page_lock);
            continue;
        }
        pthread_mutex_lock(&page->page_lock);
        pthread_mutex_unlock(&change_page_lock);

        list = page->list;
        assert(list != NULL);
        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_cool_in_dram, &cur_cool_in_nvm, page);
        #endif
        page_list_remove_page(list, page);
        // printf("Free page %lx from %s %s list\n", page->va, page->in_dram ? "DRAM" : "NVM", page->hot ? "hot" : "cold");
        if (page->in_dram) {
            enqueue_fifo(&dram_free_list, page);
        }
        else {
            enqueue_fifo(&nvm_free_list, page);
        }
        pthread_mutex_unlock(&page->page_lock);
    }

    num_ring_reqs = 0;
    // handle hot requests from hot buffer by moving pages to hot list
    while(!ring_buf_empty(hot_ring) && num_ring_reqs < HOT_RING_REQS_THRESHOLD) {
        pthread_mutex_lock(&change_page_lock);
		    page = (struct hemem_page*)ring_buf_get(hot_ring);
        if (page == NULL) {
          pthread_mutex_unlock(&change_page_lock);
            continue;
        }
        pthread_mutex_lock(&page->page_lock);
        pthread_mutex_unlock(&change_page_lock);
        if (!page->present) {
          // printf("page %lx not in hot ring\n", page->va);
          // page has been freed
          pthread_mutex_unlock(&page->page_lock);
          continue;
        }
        
        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_cool_in_dram, &cur_cool_in_nvm, page);
        #endif
        page->ring_present = false;
        num_ring_reqs++;
        make_hot(page);
        pthread_mutex_unlock(&page->page_lock);
        //printf("hot ring, hot pages:%llu\n", num_ring_reqs);
	  }

    num_ring_reqs = 0;
    // handle cold requests from cold buffer by moving pages to cold list
    while(!ring_buf_empty(cold_ring) && num_ring_reqs < COLD_RING_REQS_THRESHOLD) {
        pthread_mutex_lock(&change_page_lock);
        page = (struct hemem_page*)ring_buf_get(cold_ring);
        if (page == NULL) {
            pthread_mutex_unlock(&change_page_lock);
            continue;
        }
        pthread_mutex_lock(&page->page_lock);
        pthread_mutex_unlock(&change_page_lock);
        
        if (!page->present) {
          // page has been freed
          pthread_mutex_unlock(&page->page_lock);
          continue;
        }
        

        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_cool_in_dram, &cur_cool_in_nvm, page);
        #endif
        page->ring_present = false;
        num_ring_reqs++;
        make_cold(page);
        pthread_mutex_unlock(&page->page_lock);
        //printf("cold ring, cold pages:%llu\n", num_ring_reqs);
    }
    
    // move each hot NVM page to DRAM
    for (migrated_bytes = 0; migrated_bytes < PEBS_KSWAPD_MIGRATE_RATE;) {
      pthread_mutex_lock(&change_page_lock);
      p = dequeue_fifo(&nvm_hot_list);
      if (p == NULL) {
        pthread_mutex_unlock(&change_page_lock);
        // nothing in NVM is currently hot -- bail out
        break;
      }
      pthread_mutex_lock(&p->page_lock);
      // pthread_mutex_unlock(&change_page_lock);

#ifdef COOL_IN_PLACE
      if (p == cur_cool_in_nvm) {
        cur_cool_in_nvm = nvm_hot_list.first;
      }
#endif

      if (/*(p->accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (p->accesses[DRAMREAD] + p->accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
        // it has been cooled, need to move it into the cold list
        p->hot = false;
        enqueue_fifo(&nvm_cold_list, p); 
        pthread_mutex_unlock(&p->page_lock);
        pthread_mutex_unlock(&change_page_lock);
        continue;
      }

      for (tries = 0; tries < 2; tries++) {
        // find a free DRAM page
        // pthread_mutex_lock(&change_page_lock);
        np = dequeue_fifo(&dram_free_list);
        
        if (np != NULL) {
          pthread_mutex_lock(&np->page_lock);
          pthread_mutex_unlock(&change_page_lock);
          assert(!(np->present));

          LOG("%lx: cold %lu -> hot %lu\t slowmem.hot: %lu, slowmem.cold: %lu\t fastmem.hot: %lu, fastmem.cold: %lu\n",
                p->va, p->devdax_offset, np->devdax_offset, nvm_hot_list.numentries, nvm_cold_list.numentries, dram_hot_list.numentries, dram_cold_list.numentries);

          old_offset = p->devdax_offset;
          // printf("calling pebs_migrate_up from pebs_policy_thread for page %lx to dram offset %lx\n", p->va, np->devdax_offset);
          pebs_migrate_up(p, np->devdax_offset);
          np->devdax_offset = old_offset;
          np->in_dram = false;
          np->present = false;
          np->hot = false;
          for (int i = 0; i < NPBUFTYPES; i++) {
            np->accesses[i] = 0;
            np->tot_accesses[i] = 0;
          }

          enqueue_fifo(&dram_hot_list, p);
          enqueue_fifo(&nvm_free_list, np);

          migrated_bytes += pt_to_pagesize(p->pt);
          pthread_mutex_unlock(&np->page_lock);
          pthread_mutex_unlock(&p->page_lock);
          break;
        } else {
          pthread_mutex_unlock(&change_page_lock);
          pthread_mutex_unlock(&p->page_lock);
        }

        // no free dram page, try to find a cold dram page to move down
        pthread_mutex_lock(&change_page_lock);
        cp = dequeue_fifo(&dram_cold_list);
        if (cp == NULL) {
          // all dram pages are hot, so put it back in list we got it from
          enqueue_fifo(&nvm_hot_list, p);
          pthread_mutex_unlock(&change_page_lock);
          goto out;
        }
        pthread_mutex_lock(&cp->page_lock);
        pthread_mutex_unlock(&change_page_lock);
        assert(cp != NULL);

        // find a free nvm page to move the cold dram page to
        pthread_mutex_lock(&change_page_lock);
        np = dequeue_fifo(&nvm_free_list);
        if (np != NULL) {
          pthread_mutex_lock(&np->page_lock);
          pthread_mutex_unlock(&change_page_lock);
          assert(!(np->present));

          LOG("%lx: hot %lu -> cold %lu\t slowmem.hot: %lu, slowmem.cold: %lu\t fastmem.hot: %lu, fastmem.cold: %lu\n",
                cp->va, cp->devdax_offset, np->devdax_offset, nvm_hot_list.numentries, nvm_cold_list.numentries, dram_hot_list.numentries, dram_cold_list.numentries);

          old_offset = cp->devdax_offset;
          pebs_migrate_down(cp, np->devdax_offset);
          np->devdax_offset = old_offset;
          np->in_dram = true;
          np->present = false;
          np->hot = false;
          for (int i = 0; i < NPBUFTYPES; i++) {
            np->accesses[i] = 0;
            np->tot_accesses[i] = 0;
          }

          enqueue_fifo(&nvm_cold_list, cp);
          enqueue_fifo(&dram_free_list, np);
          pthread_mutex_unlock(&np->page_lock);
          pthread_mutex_unlock(&cp->page_lock);
        } else {
          pthread_mutex_unlock(&change_page_lock);
          pthread_mutex_unlock(&cp->page_lock);
        }
        assert(np != NULL);
      }
    }

    #ifdef COOL_IN_PLACE
    cur_cool_in_dram = partial_cool(&dram_hot_list, &dram_cold_list, true, cur_cool_in_dram);
    cur_cool_in_nvm = partial_cool(&nvm_hot_list, &nvm_cold_list, false, cur_cool_in_nvm);
    #else
    partial_cool(&dram_hot_list, &dram_cold_list, true);
    partial_cool(&nvm_hot_list, &nvm_cold_list, false);
    #endif

out:
    gettimeofday(&end, NULL);
    // elapsed time in us
    migrate_time = elapsed(&start, &end) * 1000000.0;
    if (migrate_time < (1.0 * PEBS_KSWAPD_INTERVAL)) {
      usleep((uint64_t)((1.0 * PEBS_KSWAPD_INTERVAL) - migrate_time));
    }
 
    LOG_TIME(MIGRATE, elapsed(&start, &end));
  }

  return NULL;
}

static struct hemem_page* pebs_allocate_page()
{
  struct timeval start, end;
  struct hemem_page *page;

  gettimeofday(&start, NULL);
  pthread_mutex_lock(&change_page_lock);
  page = dequeue_fifo(&dram_free_list);
  if (page != NULL) {
    pthread_mutex_lock(&page->page_lock);
    pthread_mutex_unlock(&change_page_lock);
    assert(page->in_dram);
    assert(!page->present);

    page->present = true;
    enqueue_fifo(&dram_cold_list, page);
    pthread_mutex_unlock(&page->page_lock);

    gettimeofday(&end, NULL);
    LOG_TIME(MEM_POLICY_ALLOCATE_PAGE1, elapsed(&start, &end));
    // pthread_mutex_unlock(&page->page_lock);
    return page;
  } else {
    pthread_mutex_unlock(&change_page_lock);
  }
    
  // DRAM is full, fall back to NVM
  pthread_mutex_lock(&change_page_lock);
  page = dequeue_fifo(&nvm_free_list);
  if (page != NULL) {
    pthread_mutex_lock(&page->page_lock);
    pthread_mutex_unlock(&change_page_lock);
    assert(!page->in_dram);
    assert(!page->present);

    page->present = true;
    enqueue_fifo(&nvm_cold_list, page);
    pthread_mutex_unlock(&page->page_lock);

    gettimeofday(&end, NULL);
    LOG_TIME(MEM_POLICY_ALLOCATE_PAGE2, elapsed(&start, &end));
    // pthread_mutex_unlock(&page->page_lock);
    return page;
  } else {
    pthread_mutex_unlock(&change_page_lock);
  }
  // perror("pebs_allocate_page: mmap/mlock failed");
  fprintf(stderr, "errno=%d (%s)\n", errno, strerror(errno));
  // printf("mem_allocated: %lu bytes\n", mem_allocated);
  


  assert(!"Out of memory");
  return NULL;
}

struct hemem_page* pebs_pagefault(void)
{
  struct hemem_page *page;

  // do the heavy lifting of finding the devdax file offset to place the page
  page = pebs_allocate_page();
  assert(page != NULL);

  return page;
}

void pebs_remove_page(struct hemem_page *page)
{
  assert(page != NULL);

  LOG("pebs: remove page, put this page into free_page_ring: va: 0x%lx\n", page->va);

  pthread_mutex_lock(&free_page_ring_lock);
  while (ring_buf_full(free_page_ring));
  ring_buf_put(free_page_ring, (uint64_t*)page);
  // printf("free_page_ring: %lu entries\n", ring_buf_size(free_page_ring));
  pthread_mutex_unlock(&free_page_ring_lock);

  page->present = false;
  page->hot = false;
  for (int i = 0; i < NPBUFTYPES; i++) {
    page->accesses[i] = 0;
    page->tot_accesses[i] = 0;
  }
}

void pebs_init(void)
{
  pthread_t kswapd_thread;
  pthread_t scan_thread;
  uint64_t** buffer;
  char logpath[32];

  memset(page_records, 0, MAX_PAGES * sizeof(struct pebs_record));

  internal_call++;

  LOG("pebs_init: started\n");

  snprintf(&logpath[0], sizeof(logpath) - 1, "log-hem.txt");
  miss_ratio_f = fopen(logpath, "w");
  if (miss_ratio_f == NULL) {
    perror("miss ratio file fopen");
  }
  assert(miss_ratio_f != NULL);
  miss_ratio_f_opened = true;

  char* pebs_start_cpu_string = getenv("PEBS_START_CPU");
  if(pebs_start_cpu_string != NULL)
    pebs_start_cpu = strtoull(pebs_start_cpu_string, NULL, 10);
  else
    pebs_start_cpu = START_THREAD_DEFAULT;
  
  scanning_thread_cpu = hemem_start_cpu;
  migration_thread_cpu = scanning_thread_cpu + 1 * 2;

  for (int i = pebs_start_cpu; i < pebs_start_cpu + num_cores; i++) {
    //perf_page[i][READ] = perf_setup(0x1cd, 0x4, i);  // MEM_TRANS_RETIRED.LOAD_LATENCY_GT_4
    //perf_page[i][READ] = perf_setup(0x81d0, 0, i);   // MEM_INST_RETIRED.ALL_LOADS
    perf_page[i][DRAMREAD] = perf_setup(0x1d3, 0, i * 2, DRAMREAD);      // MEM_LOAD_L3_MISS_RETIRED.LOCAL_DRAM
    perf_page[i][NVMREAD] = perf_setup(0x4d3, 0, i * 2, NVMREAD);     // MEM_LOAD_RETIRED.LOCAL_PMM
    //perf_page[i][WRITE] = perf_setup(0x82d0, 0, i, WRITE);    // MEM_INST_RETIRED.ALL_STORES
    //perf_page[i][WRITE] = perf_setup(0x12d0, 0, i);   // MEM_INST_RETIRED.STLB_MISS_STORES
  }

  size_t dram_pages = dramsize / PAGE_SIZE;
  size_t nvm_pages  = nvmsize  / PAGE_SIZE;

  // Allocate metadata arrays in one anon mapping each (zero-filled)
  LOG("PAGE_SIZE: %lu\n", PAGE_SIZE);
  LOG("DRAM pages: %ld\n", dramsize / PAGE_SIZE);
  LOG("DRAM page meta data size: %lu\n", (unsigned long)(sizeof(struct hemem_page) * dram_pages));
  struct hemem_page *dram_meta = libc_mmap(NULL, dram_pages * sizeof(struct hemem_page),
                            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(dram_meta && dram_meta != MAP_FAILED);

  LOG("NVM pages: %ld\n", nvmsize / PAGE_SIZE);
  LOG("NVM page meta data size: %lu\n", (unsigned long)(sizeof(struct hemem_page) * nvm_pages));
  struct hemem_page *nvm_meta = libc_mmap(NULL, nvm_pages * sizeof(struct hemem_page),
                          PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(nvm_meta && nvm_meta != MAP_FAILED);

  pthread_mutex_init(&(dram_free_list.list_lock), NULL);
  
  for (size_t i = 0; i < dram_pages; i++) {
    struct hemem_page *p = &dram_meta[i];                // <— no malloc/calloc
    // (mmap anon is zeroed; no memset needed)
    p->devdax_offset = i * PAGE_SIZE + dramoffset;
    p->present       = false;
    p->in_dram       = true;
    p->ring_present  = false;
    p->pt            = pagesize_to_pt(PAGE_SIZE);
    pthread_mutex_init(&(p->page_lock), NULL);
    enqueue_fifo(&dram_free_list, p);
  }

  pthread_mutex_init(&(nvm_free_list.list_lock), NULL);
  
  for (size_t i = 0; i < nvm_pages; i++) {
    struct hemem_page *p = &nvm_meta[i];                 // <— no malloc/memset(1)
    p->devdax_offset = i * PAGE_SIZE + nvmoffset;
    p->present       = false;
    p->in_dram       = false;
    p->ring_present  = false;
    p->pt            = pagesize_to_pt(PAGE_SIZE);
    pthread_mutex_init(&(p->page_lock), NULL);
    enqueue_fifo(&nvm_free_list, p);
  }

  // Ring buffers: already using libc_mmap (good)
  LOG("Creating ring buffers: 3 x (%lu)\n", sizeof(uint64_t*) * CAPACITY);
  buffer = libc_mmap(NULL, sizeof(uint64_t*) * CAPACITY,
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(buffer && buffer != MAP_FAILED);
  hot_ring = ring_buf_init(buffer, CAPACITY);

  buffer = libc_mmap(NULL, sizeof(uint64_t*) * CAPACITY,
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(buffer && buffer != MAP_FAILED);
  cold_ring = ring_buf_init(buffer, CAPACITY);

  buffer = libc_mmap(NULL, sizeof(uint64_t*) * CAPACITY,
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(buffer && buffer != MAP_FAILED);
  free_page_ring = ring_buf_init(buffer, CAPACITY);

  int r = pthread_create(&scan_thread, NULL, pebs_scan_thread, NULL);
  assert(r == 0);
  r = pthread_create(&kswapd_thread, NULL, pebs_policy_thread, NULL);
  assert(r == 0);

  
  LOG("Memory management policy is PEBS\n");

  LOG("pebs_init: finished\n");
  internal_call--;

}

void pebs_shutdown()
{
  for (int i = pebs_start_cpu; i < pebs_start_cpu + num_cores; i++) {
    for (int j = 0; j < NPBUFTYPES; j++) {
      ioctl(pfd[i][j], PERF_EVENT_IOC_DISABLE, 0);
      //munmap(perf_page[i][j], sysconf(_SC_PAGESIZE) * PERF_PAGES);
    }
  }
}

static inline double calc_miss_ratio()
{
  return ((1.0 * accesses_cnt[NVMREAD]) / (1.0 * (accesses_cnt[DRAMREAD] + accesses_cnt[NVMREAD])));
}



void pebs_stats()
{
  uint64_t total_samples = 0;
  LOG_STATS("\tdram_hot_list.numentries: [%ld]\tdram_cold_list.numentries: [%ld]\tnvm_hot_list.numentries: [%ld]\tnvm_cold_list.numentries: [%ld]\themem_pages: [%lu]\ttotal_pages: [%lu]\tzero_pages: [%ld]\tthrottle/unthrottle_cnt: [%ld/%ld]\tcools: [%ld]\n",
          dram_hot_list.numentries,
          dram_cold_list.numentries,
          nvm_hot_list.numentries,
          nvm_cold_list.numentries,
          hemem_pages_cnt,
          total_pages_cnt,
          zero_pages_cnt,
          throttle_cnt,
          unthrottle_cnt,
          cools);
  LOG_STATS("\tdram_accesses: [%lu]\tnvm_accesses: [%lu]\tsamples: [", accesses_cnt[DRAMREAD], accesses_cnt[NVMREAD]);
  for (int i = 0; i < PEBS_NPROCS ; i++) {
    LOG_STATS("%lu ", core_accesses_cnt[i]);
    total_samples += core_accesses_cnt[i];
    core_accesses_cnt[i] = 0;
  }
  LOG_STATS("]\ttotal_samples: [%lu]\n", total_samples);

  if (accesses_cnt[DRAMREAD] + accesses_cnt[NVMREAD] != 0) {
    if (miss_ratio == -1.0) {
      miss_ratio = calc_miss_ratio();
    } else {
      miss_ratio = (EWMA_FRAC * calc_miss_ratio()) + ((1 - EWMA_FRAC) * miss_ratio);
    }
  } else {
    miss_ratio = -1.0;
  }
  fprintf(miss_ratio_f, "miss_ratio: %f\n", miss_ratio);
  fflush(miss_ratio_f);

  accesses_cnt[DRAMREAD] = accesses_cnt[NVMREAD] = 0;

//  fprintf(stdout, "Total: %.2f GB DRAM, %.2f GB NVM\n",
//    (double)(dram_hot_list.numentries + dram_cold_list.numentries) * ((double)PAGE_SIZE) / (1024.0 * 1024.0 * 1024.0), 
//    (double)(nvm_hot_list.numentries + nvm_cold_list.numentries) * ((double)PAGE_SIZE) / (1024.0 * 1024.0 * 1024.0));
//  fflush(stdout);
  hemem_pages_cnt = total_pages_cnt =  throttle_cnt = unthrottle_cnt = 0;
}
