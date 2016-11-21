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

#include "svm_fifo.h"

/** create an svm fifo, in the current heap. Fails vs blow up the process */
svm_fifo_t * 
svm_fifo_create (u32 data_size_in_bytes)
{
  svm_fifo_t * f;
  pthread_mutexattr_t attr;
  pthread_condattr_t cattr;

  f = clib_mem_alloc_aligned_or_null (sizeof (*f) + data_size_in_bytes, 
                                      CLIB_CACHE_LINE_BYTES);
  if (f == 0)
    return 0;

  memset (f, 0, sizeof (*f) + data_size_in_bytes);
  f->nitems = data_size_in_bytes;

  memset (&attr, 0, sizeof (attr));
  memset (&cattr, 0, sizeof (cattr));

  if (pthread_mutexattr_init (&attr))
    clib_unix_warning ("mutexattr_init");
  if (pthread_mutexattr_setpshared (&attr, PTHREAD_PROCESS_SHARED))
    clib_unix_warning ("pthread_mutexattr_setpshared");
  if (pthread_mutex_init (&f->mutex, &attr))
    clib_unix_warning ("mutex_init");
  if (pthread_mutexattr_destroy (&attr))
    clib_unix_warning ("mutexattr_destroy");
  if (pthread_condattr_init (&cattr))
    clib_unix_warning ("condattr_init");
  if (pthread_condattr_setpshared (&cattr, PTHREAD_PROCESS_SHARED))
    clib_unix_warning ("condattr_setpshared");
  if (pthread_cond_init (&f->condvar, &cattr))
    clib_unix_warning ("cond_init1");
  if (pthread_condattr_destroy (&cattr))
    clib_unix_warning ("cond_init2");

  return (f);
}

static int svm_fifo_dequeue_internal (svm_fifo_t * f, 
                                      int pid,
                                      u32 max_bytes, 
                                      u8 * copy_here, 
                                      int nowait)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  
  if (svm_fifo_lock (f, pid, SVM_FIFO_TAG_DEQUEUE, nowait))
    return -1;                  /* lock held elsewhere */

  if (PREDICT_FALSE (f->cursize == 0))
    {
      if (nowait)
        {
          pthread_mutex_unlock (&f->mutex);
          return -2;            /* nothing in the fifo */
        }
      while (f->cursize == 0)
        pthread_cond_wait (&f->condvar, &f->mutex);
    }

  /* Number of bytes we're going to copy */
  total_copy_bytes = (f->cursize < max_bytes) ? f->cursize : max_bytes;
  
  if (PREDICT_TRUE(copy_here != 0))
    {
      /* Number of bytes in first copy segment */
      first_copy_bytes = ((f->nitems - f->head) < total_copy_bytes) 
        ? (f->nitems - f->head) : total_copy_bytes;
      clib_memcpy (copy_here, &f->data[f->head], first_copy_bytes);
      f->head += first_copy_bytes;
      f->head = (f->head == f->nitems) ? 0 : f->head;
      f->cursize -= first_copy_bytes;

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
        {
          clib_memcpy (copy_here + first_copy_bytes, 
                       &f->data[f->head], second_copy_bytes);
          f->head += second_copy_bytes;
          f->head = (f->head == f->nitems) ? 0 : f->head;
          f->cursize -= second_copy_bytes;
        }
    }
  else
    {
      /* Account for a zero-copy dequeue done elsewhere */
      ASSERT (max_bytes <= f->cursize);
      f->head += max_bytes;
      f->head = f->head % f->nitems;
      f->cursize -= max_bytes;
      total_copy_bytes = max_bytes;
    }
  svm_fifo_unlock (f);

  /* Wake up transmitter when fifo at or below 1/4 full */
  if (f->cursize <= f->nitems/4)
    pthread_cond_broadcast (&f->condvar);
  return (total_copy_bytes);
}

int svm_fifo_dequeue (svm_fifo_t * f, 
                      int pid,
                      u32 max_bytes, 
                      u8 * copy_here)
{
  return svm_fifo_dequeue_internal (f, pid, max_bytes, 
                                    copy_here, 0 /* nowait */);
}

int svm_fifo_dequeue_nowait (svm_fifo_t * f, 
                             int pid, 
                             u32 max_bytes, 
                             u8 * copy_here)
{
  return svm_fifo_dequeue_internal (f, pid, max_bytes, 
                                    copy_here, 1 /* nowait */);
}


static int svm_fifo_enqueue_internal (svm_fifo_t * f, 
                                      int pid,
                                      u32 max_bytes, 
                                      u8 * copy_from_here, 
                                      int nowait)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  int need_broadcast = 0;
  
  if (svm_fifo_lock (f, pid, SVM_FIFO_TAG_ENQUEUE, nowait))
    return -1;

  if (PREDICT_FALSE (f->cursize == f->nitems))
    {
      if (nowait)
        {
          pthread_mutex_unlock (&f->mutex);
          return -2;
        }
      while (f->cursize == f->nitems)
        pthread_cond_wait (&f->condvar, &f->mutex);
    }

  if (f->cursize == 0)
    need_broadcast = 1;

  /* Number of bytes we're going to copy */
  total_copy_bytes = (f->nitems - f->cursize) < max_bytes ? 
    (f->nitems - f->cursize) : max_bytes;
  
  if (PREDICT_TRUE(copy_from_here != 0))
    {
      /* Number of bytes in first copy segment */
      first_copy_bytes = ((f->nitems - f->tail) < total_copy_bytes) 
        ? (f->nitems - f->tail) : total_copy_bytes;

      clib_memcpy (&f->data[f->tail], copy_from_here, first_copy_bytes);
      f->tail += first_copy_bytes;
      f->tail = (f->tail == f->nitems) ? 0 : f->tail;
      f->cursize += first_copy_bytes;

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
        {
          clib_memcpy (&f->data[f->tail], copy_from_here + first_copy_bytes, 
                       second_copy_bytes);
          f->tail += second_copy_bytes;
          f->tail = (f->tail == f->nitems) ? 0 : f->tail;
          f->cursize += second_copy_bytes;
        }
    }
  else
    {
      /* Account for a zero-copy enqueue done elsewhere */
      ASSERT (max_bytes <= (f->nitems - f->cursize));
      f->tail += max_bytes;
      f->tail = f->tail % f->nitems;
      f->cursize += max_bytes;
      total_copy_bytes = max_bytes;
    }
  /* Wake up receiver when fifo non-empty */
  if (need_broadcast)
    pthread_cond_broadcast (&f->condvar);
  svm_fifo_unlock (f);
  return (total_copy_bytes);
}

int svm_fifo_enqueue (svm_fifo_t * f, 
                      int pid,
                      u32 max_bytes, 
                      u8 * copy_from_here)
{
  return svm_fifo_enqueue_internal (f, pid, max_bytes, copy_from_here,
                                    0 /* nowait */);
}

int svm_fifo_enqueue_nowait (svm_fifo_t * f, 
                             int pid,
                             u32 max_bytes, 
                             u8 * copy_from_here)
{
  return svm_fifo_enqueue_internal (f, pid, max_bytes, copy_from_here,
                                    1 /* nowait */);
}
                      
static int svm_fifo_enqueue_internal2 (svm_fifo_t * f, 
                                       int pid,
                                       u32 max_bytes, 
                                       u8 * copy_from_here)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  u32 cursize, nitems;
  
  if (PREDICT_FALSE (f->cursize == f->nitems))
    return -2;                  /* fifo stuffed */

  /* read cursize, which can only decrease while we're working */
  cursize = f->cursize;
  nitems = f->nitems;

  /* Number of bytes we're going to copy */
  total_copy_bytes = (nitems - cursize) < max_bytes ? 
    (nitems - cursize) : max_bytes;
  
  if (PREDICT_TRUE(copy_from_here != 0))
    {
      /* Number of bytes in first copy segment */
      first_copy_bytes = ((nitems - f->tail) < total_copy_bytes) 
        ? (nitems - f->tail) : total_copy_bytes;

      clib_memcpy (&f->data[f->tail], copy_from_here, first_copy_bytes);
      f->tail += first_copy_bytes;
      f->tail = (f->tail == nitems) ? 0 : f->tail;

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
        {
          clib_memcpy (&f->data[f->tail], copy_from_here + first_copy_bytes, 
                       second_copy_bytes);
          f->tail += second_copy_bytes;
          f->tail = (f->tail == nitems) ? 0 : f->tail;
        }
    }
  else
    {
      /* Account for a zero-copy enqueue done elsewhere */
      ASSERT (max_bytes <= (nitems - cursize));
      f->tail += max_bytes;
      f->tail = f->tail % nitems;
      total_copy_bytes = max_bytes;
    }

  /* Any out-of-order segments to collect? */
  if (PREDICT_FALSE(vec_len(f->offset_enqueues)))
    {
      int i;
      offset_enqueue_t *oe;
    again:
      for (i = 0; i < vec_len (f->offset_enqueues); i++)
        {
          oe = f->offset_enqueues + i;
          if (f->tail == oe->fifo_position)
            {
              total_copy_bytes += oe->length;
              f->tail += oe->length;
              f->tail %= nitems;
              vec_delete (f->offset_enqueues, 1, i);
              goto again;
            }
        }
    }

  /* Atomically increase the queue length */
  __sync_fetch_and_add (&f->cursize, total_copy_bytes);

  return (total_copy_bytes);
}

int svm_fifo_enqueue_nowait2 (svm_fifo_t * f, 
                             int pid, 
                             u32 max_bytes, 
                             u8 * copy_from_here)
{
  return svm_fifo_enqueue_internal2 (f, pid, max_bytes, copy_from_here);
}

/** Enqueue a future segment.
 * Two choices: either copies the entire segment, or copies nothing
 * Returns 0 of the entire segment was copied
 * Returns -1 if none of the segment was copied due to lack of space
 */

static int svm_fifo_enqueue_with_offset_internal2 (svm_fifo_t * f, 
                                                   int pid,
                                                   u32 offset,
                                                   u32 required_bytes, 
                                                   u8 * copy_from_here)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  u32 cursize, nitems;
  u32 tail_plus_offset;
  offset_enqueue_t * oe;
  
  ASSERT(offset > 0);

  /* read cursize, which can only decrease while we're working */
  cursize = f->cursize;
  nitems = f->nitems;

  /* Will this request fit? */
  if ((required_bytes + offset) > (nitems - cursize))
    return -1;

  /* Number of bytes we're going to copy */
  total_copy_bytes = required_bytes;
  
  tail_plus_offset = (f->tail + offset) % nitems;

  /* Sketchy idea: repeatedly plunking down the same offset segment */
  vec_foreach (oe, f->offset_enqueues)
    {
      if (oe->fifo_position == tail_plus_offset)
        {
          ASSERT (oe->length == required_bytes);
          goto found;
        }
    }
  vec_add2 (f->offset_enqueues, oe, 1);

 found:
  oe->fifo_position = tail_plus_offset;
  oe->length = required_bytes;

  /* Number of bytes in first copy segment */
  first_copy_bytes = ((nitems - tail_plus_offset) < total_copy_bytes) 
    ? (nitems - tail_plus_offset) : total_copy_bytes;
  
  clib_memcpy (&f->data[tail_plus_offset], copy_from_here, first_copy_bytes);
  tail_plus_offset += first_copy_bytes;
  tail_plus_offset %= nitems;
  
  /* Number of bytes in second copy segment, if any */
  second_copy_bytes = total_copy_bytes - first_copy_bytes;
  if (second_copy_bytes)
    {
      clib_memcpy (&f->data[tail_plus_offset], 
                   copy_from_here + first_copy_bytes, 
                   second_copy_bytes);
    }

  return (0);
}


int svm_fifo_enqueue_with_offset2 (svm_fifo_t * f, 
                                   int pid, 
                                   u32 offset,
                                   u32 required_bytes, 
                                   u8 * copy_from_here)
{
  return svm_fifo_enqueue_with_offset_internal2 
    (f, pid, offset, required_bytes, copy_from_here);
}


static int svm_fifo_dequeue_internal2 (svm_fifo_t * f, 
                                       int pid,
                                       u32 max_bytes, 
                                       u8 * copy_here)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  u32 cursize, nitems;
  
  if (PREDICT_FALSE (f->cursize == 0))
    return -2;            /* nothing in the fifo */
  
  /* read cursize, which can only increase while we're working */
  cursize = f->cursize;
  nitems = f->nitems;

  /* Number of bytes we're going to copy */
  total_copy_bytes = (cursize < max_bytes) ? cursize : max_bytes;
  
  if (PREDICT_TRUE(copy_here != 0))
    {
      /* Number of bytes in first copy segment */
      first_copy_bytes = ((nitems - f->head) < total_copy_bytes) 
        ? (nitems - f->head) : total_copy_bytes;
      clib_memcpy (copy_here, &f->data[f->head], first_copy_bytes);
      f->head += first_copy_bytes;
      f->head = (f->head == nitems) ? 0 : f->head;

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
        {
          clib_memcpy (copy_here + first_copy_bytes, 
                       &f->data[f->head], second_copy_bytes);
          f->head += second_copy_bytes;
          f->head = (f->head == nitems) ? 0 : f->head;
        }
    }
  else
    {
      /* Account for a zero-copy dequeue done elsewhere */
      ASSERT (max_bytes <= cursize);
      f->head += max_bytes;
      f->head = f->head % nitems;
      cursize -= max_bytes;
      total_copy_bytes = max_bytes;
    }

  __sync_fetch_and_sub (&f->cursize, total_copy_bytes);
  
  return (total_copy_bytes);
}

int svm_fifo_dequeue_nowait2 (svm_fifo_t * f, 
                             int pid, 
                             u32 max_bytes, 
                             u8 * copy_here)
{
  return svm_fifo_dequeue_internal2 (f, pid, max_bytes, copy_here);
}



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */