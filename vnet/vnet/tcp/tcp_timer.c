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

#include "tcp_timer.h"

u32 oingoes;

void oingo (void)
{
  oingoes++;
}

/** construct a stop-timer handle */
static inline u32 
make_stop_timer_handle (u32 ring, u32 ring_offset, u32 index_in_slot)
{
  u32 handle;

  ASSERT (ring < TW_N_RINGS);
  ASSERT (ring_offset < TW_SLOTS_PER_RING);
  ASSERT (index_in_slot < (1<<23));
  
  /* handle: 1 bit ring id | 9 bit ring_offset | 22 bit index_in_slot */

  handle = (ring<<31) | (ring_offset << 22) | index_in_slot;
  return handle;
}

/** construct an internal (pool-index, timer-id) handle */
static inline u32
make_internal_timer_handle (u32 pool_index, u32 timer_id)
{
  u32 handle;

  ASSERT (timer_id < 16);
  ASSERT (pool_index < (1<<28));
  
  handle = (timer_id << 28) | (pool_index);
  return handle;
}


/** start a tcp timer */
u32 tcp_timer_start (tcp_timer_wheel_t * tw, u32 pool_index, u32 timer_id,
                     u32 interval)
{
  u16 slow_ring_offset, fast_ring_offset;
  tcp_timer_wheel_slot_t * ts;
  u32 index_in_slot;
  u32 carry;
  u32 timer_handle;
  u32 rv;

  ASSERT(interval);

  if (pool_index == 862)
    oingo();

  fast_ring_offset = interval & TW_RING_MASK;
  fast_ring_offset += tw->current_index[TW_RING_FAST];
  carry = fast_ring_offset >= TW_SLOTS_PER_RING ? 1 : 0;
  fast_ring_offset %= TW_SLOTS_PER_RING;
  slow_ring_offset = (interval >> TW_RING_SHIFT) + carry;

  /* Timer duration exceeds ~7 hrs? Oops */
  ASSERT(slow_ring_offset < TW_SLOTS_PER_RING);

  /* Timer expires more than 51.2 seconds from now? */
  if (slow_ring_offset)
    {
      slow_ring_offset += tw->current_index[TW_RING_SLOW];
      slow_ring_offset %= TW_SLOTS_PER_RING;
      ts = &tw->w[TW_RING_SLOW][slow_ring_offset];

      index_in_slot = clib_bitmap_first_clear (ts->busy_slot_bitmap);
      ts->busy_slot_bitmap = 
        clib_bitmap_set (ts->busy_slot_bitmap, index_in_slot, 1);

      timer_handle = make_internal_timer_handle (pool_index, timer_id);

      vec_validate (ts->timer_handles, index_in_slot);
      vec_validate (ts->fast_ring_offsets, index_in_slot);

      ts->timer_handles[index_in_slot] = timer_handle;
      /* 
       * Remember the fast ring offset, needed when we demote
       * the timer to the fast wheel
       */
      ts->fast_ring_offsets[index_in_slot] = fast_ring_offset;

      /* Return the user timer-cancellation handle */
      rv = make_stop_timer_handle (TW_RING_SLOW, slow_ring_offset, 
                                   index_in_slot);
      return rv;
    }

  /* Timer expires less than 51.2 seconds from now */
  ts = &tw->w[TW_RING_FAST][fast_ring_offset];

  /* Allocate a handle element vector slot */
  index_in_slot = clib_bitmap_first_clear (ts->busy_slot_bitmap);
  ts->busy_slot_bitmap = 
    clib_bitmap_set (ts->busy_slot_bitmap, index_in_slot, 1);

  timer_handle = make_internal_timer_handle (pool_index, timer_id);

  vec_validate (ts->timer_handles, index_in_slot);
  
  ts->timer_handles[index_in_slot] = timer_handle;

  /* Give the user a handle to cancel the timer */
  rv = make_stop_timer_handle (TW_RING_FAST, fast_ring_offset, 
                                   index_in_slot);
  
  return rv;
}

/** Stop a tcp timer
 * We pass the pool_index and timer_id for consistency-checking only.
 */

void tcp_timer_stop (tcp_timer_wheel_t * tw, u32 pool_index, u32 timer_id,
                     u32 handle)
{
  u32 ring, slot, index_in_slot;
  tcp_timer_wheel_slot_t * ts;

  ring = (handle>>31);
  slot = (handle>>22) & TW_RING_MASK;
  index_in_slot = handle & ((1<<22) - 1);

  ts = &tw->w[ring][slot];

  /* slot must be busy */
  ASSERT(clib_bitmap_get (ts->busy_slot_bitmap, index_in_slot) != 0);
  
  /* handle must match */
  ASSERT(ts->timer_handles[index_in_slot]
         == make_internal_timer_handle (pool_index, timer_id));

  /* Cancel the timer */
  ts->busy_slot_bitmap 
    = clib_bitmap_set (ts->busy_slot_bitmap, index_in_slot, 0);

#if CLIB_DEBUG > 0
  /* Poison the slot */
  ts->timer_handles[index_in_slot] = ~0;
  if (ring == TW_RING_SLOW)
    ts->fast_ring_offsets[index_in_slot] = ~0;
#endif
}

/** initialize a tcp timer wheel */
void 
tcp_timer_wheel_init (tcp_timer_wheel_t * tw, 
                      void * expired_timer_callback,
                      void * new_stop_timer_handle_callback)
{
  memset (tw, 0, sizeof (*tw));
  tw->expired_timer_callback = expired_timer_callback;
  tw->new_stop_timer_handle_callback = new_stop_timer_handle_callback;
}

/** free a tcp timer wheel */
void
tcp_timer_wheel_free (tcp_timer_wheel_t * tw)
{
  int i, j;
  tcp_timer_wheel_slot_t * ts;

  for (i = 0; i < TW_N_RINGS; i++)
    {
      for (j = 0; j < TW_SLOTS_PER_RING; j++)
        {
          ts = &tw->w[i][j];
          vec_free (ts->busy_slot_bitmap);
          vec_free (ts->timer_handles);
          vec_free (ts->fast_ring_offsets);
        }
    }
  vec_free (tw->demoted_timer_handles);
  vec_free (tw->demoted_timer_offsets);
  vec_free (tw->stop_timer_callback_args);

  memset (tw, 0, sizeof (*tw));
}

/** run the tcp timer wheel. Call every 100ms. */

void tcp_timer_expire_timers (tcp_timer_wheel_t *tw, f64 now)
{
  u32 nticks, i, j;
  tcp_timer_wheel_slot_t * ts;
  u32 fast_wheel_index, slow_wheel_index;
  u32 fast_ring_offset;
  u32 timer_index;
  u32 timer_handle;
  u32 index_in_slot;
  u32 new_stop_timer_handle;

  /* Shouldn't happen */
  if (PREDICT_FALSE(now < tw->next_run_time))
    return;

  /* Number of 100ms ticks which have occurred */
  nticks = (now - tw->last_run_time) * 10.0;
  if (nticks == 0)
    return;
  
  /* Remember when we ran, compute next runtime */
  tw->next_run_time = (now + 0.1);
  tw->last_run_time = now;

  for (i = 0; i < nticks; i++)
    {
      fast_wheel_index = tw->current_index[TW_RING_FAST];

      /* 
       * If we've been around the fast ring once,
       * process one slot in the slow ring before we handle
       * the fast ring. 
       */
      if (PREDICT_FALSE(fast_wheel_index == TW_SLOTS_PER_RING))
        {
          fast_wheel_index = tw->current_index[TW_RING_FAST] = 0;

          tw->current_index[TW_RING_SLOW]++;
          tw->current_index[TW_RING_SLOW] %= TW_SLOTS_PER_RING;
          slow_wheel_index = tw->current_index[TW_RING_SLOW];

          ts = &tw->w[TW_RING_SLOW][slow_wheel_index];

          vec_reset_length (tw->demoted_timer_handles);
          vec_reset_length (tw->demoted_timer_offsets);

          clib_bitmap_foreach (timer_index, ts->busy_slot_bitmap,
          ({                     
            timer_handle = ts->timer_handles[timer_index];
            fast_ring_offset = ts->fast_ring_offsets[timer_index];
            vec_add1 (tw->demoted_timer_handles, timer_handle);
            vec_add1 (tw->demoted_timer_offsets, fast_ring_offset);
#if CLIB_DEBUG > 0
            /* Poison the slot */
            ts->timer_handles[timer_index] = ~0;
            ts->fast_ring_offsets[timer_index] = ~0;
#endif
          }));
          /* Clear the slow-ring slot busy bitmap */
          for (j = 0; j < vec_len (ts->busy_slot_bitmap); j++)
            ts->busy_slot_bitmap[j] = 0;
          vec_reset_length (ts->busy_slot_bitmap);

          /* 
           * Deal slow-ring elements into the fast ring.
           * Hand out new timer-cancellation handles
           */
          vec_reset_length (tw->stop_timer_callback_args);
          for (j = 0; j < vec_len (tw->demoted_timer_offsets); j++)
            {
              new_stop_timer_callback_args_t *a;
              /* 
               * By construction, the fast ring is processing slot 0 
               */
              fast_ring_offset = tw->demoted_timer_offsets [j];
              timer_handle = tw->demoted_timer_handles[j];
              if ((timer_handle & 0x0FFFFFFF) == 862)
                oingo();

              ts = &tw->w[TW_RING_FAST][fast_ring_offset];

              /* Allocate a fast-ring handle slot */
              index_in_slot = clib_bitmap_first_clear (ts->busy_slot_bitmap);
              ts->busy_slot_bitmap = 
                clib_bitmap_set (ts->busy_slot_bitmap, index_in_slot, 1);

              vec_validate (ts->timer_handles, index_in_slot);

              /* Our internal handle doesn't change */
              ts->timer_handles[index_in_slot] = timer_handle;

              /* But the user's stop-timer handle must change */
              new_stop_timer_handle = 
                make_stop_timer_handle (TW_RING_FAST, fast_ring_offset,
                                        index_in_slot);
              
              vec_add2 (tw->stop_timer_callback_args, a, 1);
              a->pool_index = timer_handle & 0x0FFFFFFF;
              a->timer_id = timer_handle >> 28;
              a->new_stop_timer_handle = new_stop_timer_handle;
            }
          /* Give the user new stop-timer handles */
          if (vec_len (tw->stop_timer_callback_args))
            tw->new_stop_timer_handle_callback (tw->stop_timer_callback_args);
        }

      /* Handle the fast ring */
      vec_reset_length (tw->expired_timer_handles);

      ts = &tw->w[TW_RING_FAST][fast_wheel_index];
      clib_bitmap_foreach (timer_index, ts->busy_slot_bitmap,
      ({                     
        timer_handle = ts->timer_handles[timer_index];
#if CLIB_DEBUG > 0
        /* Poison the slot */
        ts->timer_handles[timer_index] = ~0;
#endif
        vec_add1 (tw->expired_timer_handles, timer_handle);
      }));

      /* Clear the fast-ring slot busy bitmap */
      for (j = 0; j < vec_len (ts->busy_slot_bitmap); j++)
        ts->busy_slot_bitmap[j] = 0;
      vec_reset_length (ts->busy_slot_bitmap);
      
      /* If any timers expired, tell the user */
      if (vec_len (tw->expired_timer_handles))
        tw->expired_timer_callback (tw->expired_timer_handles);
      tw->current_index[TW_RING_FAST]++;
      tw->current_tick++;
    }
}

#define TCP_TIMER_TEST 1

#if TCP_TIMER_TEST > 0

typedef struct 
{
  u32 stop_timer_handle;
  u32 expected_to_expire;
} tcp_timer_test_elt_t;

typedef struct
{
  tcp_timer_test_elt_t * test_elts;
  tcp_timer_wheel_t wheel;
} tcp_timer_test_main_t;
  
tcp_timer_test_main_t tcp_timer_test_main;

static void
run_wheel (tcp_timer_wheel_t *tw, u32 n_ticks)
{
  u32 i;
  f64 now = tw->last_run_time + 0.101;

  for (i = 0; i < n_ticks; i++)
    {
      tcp_timer_expire_timers (tw, now);
      now += 0.101;
    }
}

static void expired_timer_callback (u32 * expired_timers)
{
  int i;
  u32 pool_index, timer_id;
  tcp_timer_test_elt_t * e;
  tcp_timer_test_main_t * tm = &tcp_timer_test_main;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      ASSERT(timer_id == 3);

      e = pool_elt_at_index (tm->test_elts, pool_index);

      if (e->expected_to_expire != tm->wheel.current_tick)
        {
          fformat (stdout, "[%d] expired at %d not %d\n",
                   e - tm->test_elts, tm->wheel.current_tick,
                   e->expected_to_expire);
        }
      pool_put (tm->test_elts, e);
    }
}

static void 
new_stop_timer_handle_callback (new_stop_timer_callback_args_t *a_vec)
{
  int i;
  new_stop_timer_callback_args_t *a;
  tcp_timer_test_main_t *tm = &tcp_timer_test_main;
  tcp_timer_test_elt_t * e;

  for (i = 0; i < vec_len (a_vec); i++)
    {
      a = a_vec + i;

      e = pool_elt_at_index (tm->test_elts, a->pool_index);
      ASSERT (a->timer_id == 3);
      e->stop_timer_handle = a->new_stop_timer_handle;

      if (0 && i == 3)
        {
          tcp_timer_stop (&tm->wheel, e - tm->test_elts, 3 /* timer id*/,
                          e->stop_timer_handle);
        }
    }
}

#define NTIMERS 200000

static void
test1 (tcp_timer_test_main_t *tm)
{
  u32 i;
  tcp_timer_test_elt_t * e;
  u32 offset;

  tcp_timer_wheel_init (&tm->wheel, expired_timer_callback,
                        new_stop_timer_handle_callback);

  /* Prime offset */
  offset = 227989; 

  run_wheel(&tm->wheel, offset);
  
  fformat (stdout, "initial wheel time %d, slow index %d fast index %d\n",
           tm->wheel.current_tick, tm->wheel.current_index[TW_RING_SLOW],
           tm->wheel.current_index [TW_RING_FAST]);

  for (i = 0; i < NTIMERS; i++)
    {
      pool_get (tm->test_elts, e);
      memset (e, 0, sizeof (*e));
      e->expected_to_expire = i+offset+1;
      e->stop_timer_handle = tcp_timer_start (&tm->wheel, 
                                              e - tm->test_elts, 
                                              3 /* timer id */,
                                              i+1 /* expiration time */);
    }
  run_wheel (&tm->wheel, NTIMERS+3);

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
             pool_elts (tm->test_elts));

  pool_foreach (e, tm->test_elts,
  ({
    fformat (stdout, "[%d] expected to expire %d\n", e - tm->test_elts,
             e->expected_to_expire);
  }));
                  
  fformat (stdout, "final wheel time %d, slow index %d fast index %d\n",
           tm->wheel.current_tick, tm->wheel.current_index[TW_RING_SLOW],
           tm->wheel.current_index [TW_RING_FAST]);

  pool_free (tm->test_elts);
  tcp_timer_wheel_free (&tm->wheel);
}

static clib_error_t *
timer_test_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{

  test1 (&tcp_timer_test_main);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (timer_test_command, static) = 
{
  .path = "tcp timer test",
  .short_help = "tcp timer test",
  .function = timer_test_command_fn,
};
/* *INDENT-ON* */

#endif /* TCP_TIMER_TEST */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
