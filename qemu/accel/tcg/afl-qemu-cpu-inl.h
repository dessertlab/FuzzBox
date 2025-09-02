#include <sys/shm.h>
#include <sys/mman.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "libAFL/config.h" // CONTAINS MAP SIZE

/* Map size for the traced binary (2^MAP_SIZE_POW2) */

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */
static int setup_flag1 = 0;

#define AFL_QEMU_CPU_SNIPPET(pc) \ 
   do                            \
   {                             \
      if (setup_flag1 == 0)      \
      {                          \
         afl_setup();            \
         setup_flag1 = 1;        \
      }                          \
      afl_maybe_log(pc);         \
   } while (0)

typedef unsigned char u8;
/* Bitmap definition */
static u8 *afl_area_ptr;
static u8 *block_coverage_ptr;
static int shm_fd;
static int shm_fd2;

/* Function declarations */
static inline void afl_setup(void);
static inline void afl_maybe_log(target_ulong);

/* Set up SHM region and initialize other stuff. */
static inline void afl_setup(void)
{

   printf("AFL setup\n");
   // edge coverage bitmap (usata)
   shm_fd = shm_open(SHM_FILE, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO); // 0666);
   if (shm_fd == -1)
   {
      printf("Error in shm_open()\n");
      exit(1);
   }

   if (ftruncate(shm_fd, sizeof(u8) * MAP_SIZE) == -1)
   {
      printf("Error in ftruncate()\n");
      exit(1);
   }

   afl_area_ptr = mmap(NULL, sizeof(u8) * MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
   if (afl_area_ptr == MAP_FAILED)
   {
      printf("Error in mmap()\n");
      exit(1);
   }

   memset(afl_area_ptr, 0x00, sizeof(u8) * MAP_SIZE);
   afl_area_ptr[0] = 0x01;

   // block coverage bitmap (per grafici)
   shm_fd2 = shm_open(SHM_FILE_BLOCK_COV, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO); // 0666);
   if (shm_fd2 == -1)
   {
      printf("Error in shm_open()\n");
      exit(1);
   }

   if (ftruncate(shm_fd2, sizeof(u8) * MAP_SIZE) == -1)
   {
      printf("Error in ftruncate()\n");
      exit(1);
   }

   block_coverage_ptr = mmap(NULL, sizeof(u8) * MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd2, 0);
   if (afl_area_ptr == MAP_FAILED)
   {
      printf("Error in mmap()\n");
      exit(1);
   }

   memset(block_coverage_ptr, 0x00, sizeof(u8) * MAP_SIZE);
   block_coverage_ptr[0] = 0x01;

   printf("SHM setup ok\n");
}

static inline target_ulong aflHash(target_ulong cur_loc)
{

   /* Looks like QEMU always maps to fixed locations, so ASAN is not a
      concern. Phew. But instruction addresses may be aligned. Let's mangle
      the value to get something quasi-uniform. */
   target_ulong h = cur_loc;
#if TARGET_LONG_BITS == 32
   h ^= cur_loc >> 16;
   h *= 0x85ebca6b;
   h ^= h >> 13;
   h *= 0xc2b2ae35;
   h ^= h >> 16;
#else
   h ^= cur_loc >> 33;
   h *= 0xff51afd7ed558ccd;
   h ^= h >> 33;
   h *= 0xc4ceb9fe1a85ec53;
   h ^= h >> 33;
#endif

   h &= MAP_SIZE - 1;

   /* Implement probabilistic instrumentation by looking at scrambled block
      address. This keeps the instrumented locations stable across runs. */
   if (h >= MAP_SIZE)
   {
      return 0;
   }

   return h;
}

static inline void afl_maybe_log(target_ulong cur_loc)
{
   //if(!FEEDBACK_MODE) return; // inutile calcolare la bitmap se non c'è feedback
   static __thread target_ulong prev_loc;

   // cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
   // cur_loc &= MAP_SIZE - 1;
   cur_loc = aflHash(cur_loc); // alternative hash calculator

   // prev_loc = 0; //if onTranslation update bitmap

   if (!BLOCKCOV_MODE && !SAVE_METRICS) // blockcov mode=0, save_metrics=0 solo edge coverage
   {
      target_ulong index = cur_loc ^ prev_loc;
      if (index < MAP_SIZE) // edge coverage update
      {
         if (afl_area_ptr[index] < 0xff)
         {
            // afl_area_ptr[index]=0xff; for onTranslation bitmap is better
            afl_area_ptr[index]++;
         }

         prev_loc = cur_loc >> 1;
      }
   }
   else if (BLOCKCOV_MODE && !SAVE_METRICS) // blockcov mode=1, save_metrics=0 solo blockcov salvata e usata
   {
      if (cur_loc < MAP_SIZE) // block coverage update
      {
         if (block_coverage_ptr[cur_loc] < 0xff)
         {
            block_coverage_ptr[cur_loc]++;
         }
      }
   }
   else
   {

      target_ulong index = cur_loc ^ prev_loc;
      if (index < MAP_SIZE) // edge coverage update
      {
         if (afl_area_ptr[index] < 0xff)
         {
            // afl_area_ptr[index]=0xff; for onTranslation bitmap is better
            afl_area_ptr[index]++;
         }

         prev_loc = cur_loc >> 1;
      }
      if (cur_loc < MAP_SIZE) // block coverage update
      {
         if (block_coverage_ptr[cur_loc] < 0xff)
         {
            block_coverage_ptr[cur_loc]++;
         }
      }
   }
}
