/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "svm_fifo_segment.h"

svm_fifo_segment_main_t svm_fifo_segment_main;

/** (master) create an svm fifo segment */
int
svm_fifo_segment_create (svm_fifo_segment_create_args_t * a)
{
  int rv;
  svm_fifo_segment_private_t * s;
  svm_fifo_segment_main_t * sm = &svm_fifo_segment_main;
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t * fsh;
  void * oldheap;

  /* Allocate a fresh segment */
  vec_add2 (sm->segments, s, 1);

  memset (s, 0, sizeof (*s));

  s->ssvm.ssvm_size = a->segment_size;
  s->ssvm.i_am_master = 1;
  s->ssvm.my_pid = getpid();
  s->ssvm.name = (u8 *) a->segment_name;
  s->ssvm.requested_va = sm->next_baseva;
  
  rv = ssvm_master_init (&s->ssvm, s - sm->segments);

  if (rv)
    {
      _vec_len(s) = vec_len(s) - 1;
      return (rv);
    }

  /* Note; requested_va updated due to seg base addr randomization */
  sm->next_baseva = s->ssvm.requested_va + a->segment_size;

  sh = s->ssvm.sh;
  oldheap = ssvm_push_heap (sh);

  /* Set up svm_fifo_segment shared header */
  fsh = clib_mem_alloc (sizeof (*fsh));
  memset (fsh, 0, sizeof (*fsh));
  sh->opaque [0] = fsh;
  s->h = fsh;
  fsh->segment_name = format (0, "%s%c", a->segment_name, 0);

  /* Avoid vec_add1(...) failure when adding a fifo, etc. */
  vec_validate (fsh->fifos, 64);
  _vec_len (fsh->fifos) = 0;

  ssvm_pop_heap (oldheap);

  sh->ready = 1;
  a->rv = s;
  return (0);
}

/** (slave) attach to an svm fifo segment */
int
svm_fifo_segment_attach (svm_fifo_segment_create_args_t * a)
{
  int rv;
  svm_fifo_segment_private_t * s;
  svm_fifo_segment_main_t * sm = &svm_fifo_segment_main;
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t * fsh;

  /* Allocate a fresh segment */
  vec_add2 (sm->segments, s, 1);

  memset (s, 0, sizeof (*s));

  s->ssvm.ssvm_size = a->segment_size;
  s->ssvm.my_pid = getpid();
  s->ssvm.name = (u8 *) a->segment_name;
  s->ssvm.requested_va = sm->next_baseva;
  
  rv = ssvm_slave_init (&s->ssvm, sm->timeout_in_seconds);

  if (rv)
    {
      _vec_len(s) = vec_len(s) - 1;
      return (rv);
    }

  /* Fish the segment header */
  sh = s->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];
  s->h = fsh;

  a->rv = s;
  return (0);
}

svm_fifo_t *
svm_fifo_segment_alloc_fifo (svm_fifo_segment_private_t * s,
                             u32 data_size_in_bytes)
{
  ssvm_shared_header_t *sh;
  svm_fifo_t * f;
  void * oldheap;
  
  sh = s->ssvm.sh;
  oldheap = ssvm_push_heap (sh);

  /* Note: this can fail, in which case: create another segment */
  f = svm_fifo_create (data_size_in_bytes);
  if (f == 0)
    {
      ssvm_pop_heap (oldheap);
      return (0);
    }
  
  ssvm_pop_heap (oldheap);
  return (f);
}

void
svm_fifo_segment_free_fifo (svm_fifo_segment_private_t * s,
                            svm_fifo_t * f)
{
  ssvm_shared_header_t *sh;
  void * oldheap;
  
  sh = s->ssvm.sh;
  oldheap = ssvm_push_heap (sh);
  
  clib_mem_free (f);
  ssvm_pop_heap (oldheap);
}

void svm_fifo_segment_init (void)
{
  svm_fifo_segment_main_t * sm = &svm_fifo_segment_main;

  sm->next_baseva = 0x200000000ULL;
  sm->timeout_in_seconds = 20;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
