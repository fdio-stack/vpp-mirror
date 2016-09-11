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
#ifndef __included_ssvm_fifo_h__
#define __included_ssvm_fifo_h__

typedef enum 
{
  SVM_FIFO_TAG_NOT_HELD = 0,
  SVM_FIFO_TAG_DEQUEUE,
  SVM_FIFO_TAG_ENQUEUE,
} svm_lock_tag_t;

typedef struct
{
  pthread_mutex_t mutex;	/* 8 bytes */
  pthread_cond_t condvar;	/* 8 bytes */
  u32 owner_pid;
  svm_lock_tag_t tag;
  u32 head;
  u32 tail;
  u32 cursize;
  u32 nitems;
  
  CLIB_CACHE_LINE_ALIGN_MARK (data);
} svm_fifo_t;

static inline int svm_fifo_lock (svm_fifo_t * f, u32 pid, u32 tag, int nowait)
{
  ASSERT (f->owner_pid != pid);
  if (PREDICT_TRUE (nowait == 0))
    pthread_mutex_lock (&f->mutex);
  else
    {
      if (pthread_mutex_trylock (&f->mutex))
        return -1;
    }
  f->owner_pid = pid;
  f->tag = tag;
  return 0;
}

static inline void svm_fifo_unlock (svm_fifo_t * f)
{
  f->owner_pid = 0;
  f->tag = 0;
  CLIB_MEMORY_BARRIER();
  pthread_mutex_unlock (&f->mutext);
}

static inline u32 svm_fifo_max_dequeue (svm_fifo_t * f)
{
  return f->nitems;
}

static inline u32 svm_fifo_max_enqueue (svm_fifo_t * f)
{
  return f->nitems - f->nitems;
}

svm_fifo_t * 
svm_fifo_create (u32 data_size_in_bytes);

#endif /* __included_ssvm_fifo_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
