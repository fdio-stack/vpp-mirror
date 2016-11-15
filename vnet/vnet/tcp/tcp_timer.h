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
#ifndef __included_tcp_timer_h__
#define __included_tcp_timer_h__

#include <vnet/vnet.h>

/** @file
 *  @brief TCP timer definitions
 *
 * Design parameters:
 *  granularity: 100ms
 *  required max period: 2.5 hours => 150 minutes => 90,000 ticks
 *  Rounding up to 256k ticks yields a two-level 512 slot-per-level
 *  wheel, resulting in a 7-hour max period.
 */

typedef struct
{
  /** Busy indices in timer_handles, fast_ring_offsets */
  uword *busy_slot_bitmap;
  /** Timers which expire in this interval */
  u32 *timer_handles;
  /** Slow ring only, saved when timer added to ring */
  u16 *fast_ring_offsets;
} tcp_timer_wheel_slot_t;

typedef enum
{
  /** Fast timer ring ID */
  TW_RING_FAST,
  /** Slow timer ring ID */
  TW_RING_SLOW,
  /** Number of timer rings */
  TW_N_RINGS,
} tw_ring_index_t;

#define TW_SLOTS_PER_RING 512
#define TW_RING_SHIFT 9
#define TW_RING_MASK (TW_SLOTS_PER_RING -1)

typedef struct
{
  /** pool index which needs a new timer cancellation handle */
  u32 pool_index;

  /** new timer cancellation handle */
  u32 new_stop_timer_handle;

  /** timer which needs a new cancellation handle */
  u8 timer_id;
} new_stop_timer_callback_args_t;

typedef struct
{
  /** Next time the wheel should run */
  f64 next_run_time;

  /** Last time the wheel ran */
  f64 last_run_time;

  /** current tick */
  u32 current_tick;

  /** current wheel indices */
  u32 current_index[TW_N_RINGS];

  /** wheel arrays */
  tcp_timer_wheel_slot_t w[TW_N_RINGS][TW_SLOTS_PER_RING];

  /** expired timer callback, receives a vector of handles */
  void (*expired_timer_callback)(u32 * expired_timer_handles);

  /** new stop-timer handle callback, receives a vector */
  void (*new_stop_timer_handle_callback)(new_stop_timer_callback_args_t *);

  /** vector of expired timers */
  u32 * expired_timer_handles;

  /** vector of timers to move from the slow wheel to the fast wheel */
  u32 * demoted_timer_handles;

  /** vector of fast wheel offsets, used during move from
      slow wheel to the fast wheel */
  u32 * demoted_timer_offsets;

  /** vector of new stop-timer handles, used during move to fast wheel */
  new_stop_timer_callback_args_t *stop_timer_callback_args;
} tcp_timer_wheel_t;

/** start a tcp timer */
u32 tcp_timer_start (tcp_timer_wheel_t * tw, u32 pool_index, u32 timer_id,
                     u32 interval);

/** Stop a tcp timer */
void tcp_timer_stop (tcp_timer_wheel_t * tw, u32 pool_index, u32 timer_id,
                     u32 handle);

/** Initialize a tcp timer wheel */
void
tcp_timer_wheel_init (tcp_timer_wheel_t * tw,
                      void * expired_timer_callback,
                      void * new_stop_timer_handle_callback);

/** free a tcp timer wheel */
void
tcp_timer_wheel_free (tcp_timer_wheel_t * tw);

/** run the tcp timer wheel. Call every 100ms. */
void
tcp_timer_expire_timers (tcp_timer_wheel_t *tw, f64 now);

#endif /* __included_tcp_timer_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
