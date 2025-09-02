#ifndef AFL_RAND_H
#define AFL_RAND_H

#include <fcntl.h>
#include "libAFL/types.h"
#include "libAFL/common.h"
#include "libAFL/xxh3.h"

//#define UINT64_MAX  0xffffffffffffffffULL 

typedef struct afl_rand {

  u32  rand_cnt;                                                                            /* Random number counter*/
  u64  rand_seed[4];
  s32  dev_urandom_fd;
  s64  init_seed;
  bool fixed_seed;
} afl_rand_t;


u64 afl_rand_below(afl_rand_t *rnd, u64 limit);
u64 afl_rand_between(afl_rand_t *rand, u64 min, u64 max);
afl_ret_t afl_rand_init_fixed_seed(afl_rand_t *rnd, s64 init_seed);
afl_ret_t afl_rand_init(afl_rand_t *rnd);
u64 afl_rand_next(afl_rand_t *rnd);
void afl_rand_deinit(afl_rand_t *rnd);

AFL_NEW_AND_DELETE_FOR(afl_rand);

#endif                                                                                                /* AFL_RAND_H */

