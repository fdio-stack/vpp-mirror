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
  u32 actual_bytes, nbytes;
  
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
  actual_bytes = f->cursize < max_bytes ? f->cursize : max_bytes;
  
  if (PREDICT_TRUE(copy_here != 0))
    {
      /* Number of bytes in first copy segment */
      nbytes = ((f->nitems - f->head) < max_bytes) ? f->nitems - f->head :
        actual_bytes;
      clib_memcpy (copy_here, &f->data[f->head], nbytes);
      f->head += nbytes;
      f->head = (f->head == f->nitems) ? 0 : f->head;
      f->cursize -= nbytes;

      /* Number of bytes in second copy segment, if any */
      nbytes = actual_bytes - nbytes;
      if (nbytes)
        {
          clib_memcpy (copy_here + nbytes, &f->data[f->head], actual_bytes);
          f->head += actual_bytes;
          f->head = (f->head == f->nitems) ? 0 : f->head;
          f->cursize -= nbytes;
        }
    }
  else
    {
      /* Account for a zero-copy dequeue done elsewhere */
      ASSERT (max_bytes <= f->cursize);
      f->head += max_bytes;
      f->head = f->head % f->nitems;
      f->cursize -= max_bytes;
      actual_bytes = max_bytes;
    }
  svm_fifo_unlock (f);

  /* Wake up transmitter when fifo at or below 1/4 full */
  if (f->cursize <= f->nitems/4)
    pthread_cond_broadcast (&f->condvar);
  return (actual_bytes);
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
  u32 actual_bytes, nbytes;
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
  actual_bytes = (f->nitems - f->cursize) < max_bytes ? 
    (f->nitems - f->cursize) : max_bytes;
  
  if (PREDICT_TRUE(copy_from_here != 0))
    {
      /* Number of bytes in first copy segment */
      nbytes = ((f->nitems - f->tail) < max_bytes) ? f->nitems - f->tail :
        actual_bytes;
      clib_memcpy (&f->data[f->tail], copy_from_here, nbytes);
      f->tail += nbytes;
      f->tail = (f->tail == f->nitems) ? 0 : f->tail;
      f->cursize += nbytes;

      /* Number of bytes in second copy segment, if any */
      nbytes = actual_bytes - nbytes;
      if (nbytes)
        {
          clib_memcpy (&f->data[f->tail], copy_from_here + nbytes, 
                       actual_bytes);
          f->tail += actual_bytes;
          f->tail = (f->tail == f->nitems) ? 0 : f->tail;
          f->cursize += nbytes;
        }
    }
  else
    {
      /* Account for a zero-copy enqueue done elsewhere */
      ASSERT (max_bytes <= (f->nitems - f->cursize));
      f->tail += max_bytes;
      f->tail = f->tail % f->nitems;
      f->cursize += max_bytes;
      actual_bytes = max_bytes;
    }
  /* Wake up receiver when fifo non-empty */
  if (need_broadcast)
    pthread_cond_broadcast (&f->condvar);
  svm_fifo_unlock (f);
  return (actual_bytes);
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
