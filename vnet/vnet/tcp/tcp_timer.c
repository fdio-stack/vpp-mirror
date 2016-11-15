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

/** @file
 *  @brief TCP timer implementation
 */

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


/**
 * @brief Start a Tcp Timer
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 * @param u32 pool_index user pool index, presumably for a tcp session
 * @param u32 timer_id app-specific timer ID. 4 bits.
 * @param u32 interval timer interval in 100ms ticks
 * @returns handle needed to cancel the timer
 */
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

/**
 * @brief Stop a tcp timer
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 * @param u32 pool_index user pool index, passed for consistency checking only
 * @param u32 timer_id 4 bit timer ID, passed for consistency checking only
 * @param u32 handle timer cancellation returned by tcp_timer_start
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

/**
 * @brief Initialize a tcp timer wheel
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 * @param void * expired_timer_callback. Passed a u32 * vector of
 *   expired timer handles.
 * @param void * new_stop_timer_handle_callback. Passed a vector of
 *   new_stop_timer_callback_args_t handles, corresponding to
 *   timers moved from the slow ring to the fast ring. Called approximately
 *   once every 51 seconds.
 */
void
tcp_timer_wheel_init (tcp_timer_wheel_t * tw,
                      void * expired_timer_callback,
                      void * new_stop_timer_handle_callback)
{
  memset (tw, 0, sizeof (*tw));
  tw->expired_timer_callback = expired_timer_callback;
  tw->new_stop_timer_handle_callback = new_stop_timer_handle_callback;
}

/**
 * @brief Free a tcp timer wheel
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 */
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

/**
 * @brief Advance a tcp timer wheel. Calls the expired timer callback
 * as needed. This routine should be called once every 100ms.
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 * @param f64 now the current time, e.g. from vlib_time_now(vm)
 */
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
  /** Handle returned from tcp_start_timer */
  u32 stop_timer_handle;

  /** Test item should expire at this clock tick */
  u32 expected_to_expire;
} tcp_timer_test_elt_t;

typedef struct
{
  /** Pool of test objects */
  tcp_timer_test_elt_t * test_elts;

  /** The timer wheel */
  tcp_timer_wheel_t wheel;

  /** random number seed */
  u32 seed;

  /** number of timers */
  u32 ntimers;

  /** number of "churn" iterations */
  u32 niter;

  /** number of clock ticks per churn iteration */
  u32 ticks_per_iter;
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

/**
 * @brief Canonical wheel demotion handle reset callback
 * @param new_stop_timer_callback_args_t * a_vec
 *
 * Real applications can just about steal this callback verbatim.
 * Change tcp_timer_test_elt_t to <whatever>, and off you go
 */
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
    }
}

static clib_error_t *
test2 (vlib_main_t * vm, tcp_timer_test_main_t *tm)
{
  u32 i, j;
  tcp_timer_test_elt_t * e;
  u32 initial_wheel_offset;
  u32 expiration_time;
  u32 max_expiration_time = 0;
  u32 * deleted_indices = 0;
  u32 adds = 0, deletes = 0;
  f64 before, after;

  tcp_timer_wheel_init (&tm->wheel, expired_timer_callback,
                        new_stop_timer_handle_callback);

  /* Prime offset */
  initial_wheel_offset = 757;

  run_wheel(&tm->wheel, initial_wheel_offset);

  vlib_cli_output (vm, "test %d timers, %d iter, %d ticks per iter, 0x%x seed",
                   tm->ntimers, tm->niter, tm->ticks_per_iter, tm->seed);

  before = vlib_time_now (vm);

  /* Prime the pump */
  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      memset (e, 0, sizeof (*e));

      do {
        expiration_time = random_u32 (&tm->seed) & ((1<<17) - 1);
      } while (expiration_time == 0);

      if (expiration_time > max_expiration_time)
        max_expiration_time = expiration_time;

      e->expected_to_expire = expiration_time + initial_wheel_offset;
      e->stop_timer_handle = tcp_timer_start (&tm->wheel,
                                              e - tm->test_elts,
                                              3 /* timer id */,
                                              expiration_time);
    }

  adds += i;

  for (i = 0; i < tm->niter; i++)
    {
      run_wheel (&tm->wheel, tm->ticks_per_iter);

      j = 0;
      vec_reset_length (deleted_indices);
      pool_foreach (e, tm->test_elts,
      ({
        tcp_timer_stop (&tm->wheel, e - tm->test_elts, 3 /* timer id*/,
                        e->stop_timer_handle);
        vec_add1 (deleted_indices, e - tm->test_elts);
        if (++j >= tm->ntimers/4)
          goto del_and_re_add;
      }));

    del_and_re_add:
      for (j = 0; j < vec_len (deleted_indices); j++)
        pool_put_index (tm->test_elts, deleted_indices[j]);

      deletes += j;

      for (j = 0; j < tm->ntimers/4; j++)
        {
          pool_get (tm->test_elts, e);
          memset (e, 0, sizeof (*e));

          do {
            expiration_time = random_u32 (&tm->seed) & ((1<<17) - 1);
          } while (expiration_time == 0);

          if (expiration_time > max_expiration_time)
            max_expiration_time = expiration_time;

          e->expected_to_expire = expiration_time + tm->wheel.current_tick;
          e->stop_timer_handle = tcp_timer_start (&tm->wheel,
                                                  e - tm->test_elts,
                                                  3 /* timer id */,
                                                  expiration_time);
        }
      adds += j;
    }

  vec_free (deleted_indices);

  run_wheel (&tm->wheel, max_expiration_time + 1);

  after = vlib_time_now (vm);

  vlib_cli_output (vm, "%d adds, %d deletes, %d ticks", adds, deletes,
                   tm->wheel.current_tick);
  vlib_cli_output (vm, "test ran %.2f seconds, %.2f ops/second",
                   (after - before),
                   ((f64)adds + (f64) deletes + (f64)tm->wheel.current_tick)
                   / (after - before));

  if (pool_elts (tm->test_elts))
    vlib_cli_output (vm, "Note: %d elements remain in pool\n",
             pool_elts (tm->test_elts));

  pool_foreach (e, tm->test_elts,
  ({
    vlib_cli_output (vm, "[%d] expected to expire %d\n", e - tm->test_elts,
             e->expected_to_expire);
  }));

  pool_free (tm->test_elts);
  tcp_timer_wheel_free (&tm->wheel);
  return 0;
}

static clib_error_t *
test1 (vlib_main_t * vm, tcp_timer_test_main_t *tm)
{
  u32 i;
  tcp_timer_test_elt_t * e;
  u32 offset;

  tcp_timer_wheel_init (&tm->wheel, expired_timer_callback,
                        new_stop_timer_handle_callback);

  /*
   * Prime offset, to make sure that the wheel starts in a
   * non-trivial position
   */
  offset = 227989;

  run_wheel(&tm->wheel, offset);

  vlib_cli_output
    (vm, "initial wheel time %d, slow index %d fast index %d\n",
     tm->wheel.current_tick, tm->wheel.current_index[TW_RING_SLOW],
     tm->wheel.current_index [TW_RING_FAST]);

  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      memset (e, 0, sizeof (*e));
      e->expected_to_expire = i+offset+1;
      e->stop_timer_handle = tcp_timer_start (&tm->wheel,
                                              e - tm->test_elts,
                                              3 /* timer id */,
                                              i+1 /* expiration time */);
    }
  run_wheel (&tm->wheel, tm->ntimers+3);

  if (pool_elts (tm->test_elts))
    vlib_cli_output (vm, "Note: %d elements remain in pool\n",
             pool_elts (tm->test_elts));

  pool_foreach (e, tm->test_elts,
  ({
    vlib_cli_output (vm, "[%d] expected to expire %d\n", e - tm->test_elts,
                     e->expected_to_expire);
  }));

  vlib_cli_output
    (vm, "final wheel time %d, slow index %d fast index %d\n",
     tm->wheel.current_tick, tm->wheel.current_index[TW_RING_SLOW],
     tm->wheel.current_index [TW_RING_FAST]);

  pool_free (tm->test_elts);
  tcp_timer_wheel_free (&tm->wheel);
  return 0;
}

static clib_error_t *
timer_test_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{

  tcp_timer_test_main_t *tm = &tcp_timer_test_main;
  int is_test1 = 0;
  int is_test2 = 0;

  memset (tm, 0, sizeof(*tm));
  /* Default values */
  tm->ntimers = 100000;
  tm->seed = 0xDEADDABE;
  tm->niter = 1000;
  tm->ticks_per_iter = 727;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "seed %d", &tm->seed))
        ;
      else if (unformat (input, "test1"))
        is_test1 = 1;
      else if (unformat (input, "test2"))
        is_test2 = 1;
      else if (unformat (input, "ntimers %d", &tm->ntimers))
        ;
      else if (unformat (input, "niter %d", &tm->niter))
        ;
      else if (unformat (input, "ticks_per_iter %d", &tm->ticks_per_iter))
        ;
    }

  if (is_test1 + is_test2 == 0)
    return clib_error_return (0, "No test specified [test1..n]");

  if (is_test1)
    return test1 (vm, &tcp_timer_test_main);
  if (is_test2)
    return test2 (vm, &tcp_timer_test_main);

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
