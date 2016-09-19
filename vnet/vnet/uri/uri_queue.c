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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>

#include "uri.h"

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <ip/udp_packet.h>

static u32 (*event_queue_tx_fns)(vlib_main_t *, stream_session_t *,
                                 vlib_buffer_t *) [SESSION_TYPE_N_TYPES] = 
{
#define _(A,a) uri_tx_##a,
  foreach_uri_session_type
#undef _
};

vlib_node_registration_t uri_queue_node;

typedef struct 
{
  u32 next_index;
  u32 sw_if_index;
} uri_queue_trace_t;

/* packet trace format function */
static u8 * format_uri_queue_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  uri_queue_trace_t * t = va_arg (*args, uri_queue_trace_t *);
  
  s = format (s, "URI_QUEUE: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}

vlib_node_registration_t uri_queue_node;

#define foreach_uri_queue_error \
_(SWAPPED, "Mac swap packets processed")

typedef enum {
#define _(sym,str) URI_QUEUE_ERROR_##sym,
  foreach_uri_queue_error
#undef _
  URI_QUEUE_N_ERROR,
} uri_queue_error_t;

static char * uri_queue_error_strings[] = {
#define _(sym,string) string,
  foreach_uri_queue_error
#undef _
};

static uword
uri_queue_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  stream_server_main_t *ssm = &stream_server_main;
  u32 n_left_from, * from, * to_next;
  u32 next_index;
  u32 n_left_to_next, *to_next;
  uri_queue_next_t next_index;
  u32 * my_tx_buffers;
  fifo_event_t * my_fifo_events, *e0;
  u32 n_to_dequeue, n_free_buffers;
  u32 buffer_freelist_index;
  int i;
  unix_shared_memory_queue * q;
  int n_tx_packets;
  u32 last_put_next = ~0;
  u32 n_trace = vlib_get_trace_count (vm, node);

  my_tx_buffers = vec_elt_at_index (ssm->tx_buffers, vm->cpu_index);

  /* min number of events we can dequeue without blocking */
  n_to_dequeue = q->cursize;

  /* $$$ config parameter */
  if (PREDICT_FALSE(vec_len (my_tx_buffers) < n_to_dequeue))
    {
      uword len = vec_len(my_tx_buffers);
      /* $$$ config parameter */
      n_free_buffers = (n_to_dequeue > 32) ? n_to_dequeue : 32;
      vec_validate (my_tx_buffers, n_free_buffers - 1);

      _vec_len(my_tx_buffers) +=
        vlib_buffer_alloc_from_free_list
        (vm, my_tx_buffers[len], n_free_buffers - len, 
         VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
    }
  
  ssm->tx_buffers[vm->cpu_index] = my_tx_buffers;

  /* Buffer shortage? Try again later... */
  if (vec_len (n_free_buffers) < n_to_dequeue)
    return 0;
  
  my_fifo_events = ssm->fifo_events[vm->cpu_index];

  q = ssm->vpp_event_queue;

  /* See you in the next life, don't be late */
  if (pthread_mutex_trylock (&q->mutex))
    return 0;
  
  vec_reset_length (my_fifo_events);

  for (i = 0; i < n_to_dequeue; i++)
    {
      vec_add2 (my_fifo_events, e, 1);
      unix_shared_memory_queue_sub_raw (q, e);
      n_to_dequeue--;
    }
  pthread_mutex_unlock (&q->mutex);

  ssm->fifo_events[vm->cpu_index] = my_fifo_events;

  buffer_freelist_index = _vec_len (my_tx_buffers)-1;

  next_index = node->cached_next_index;

  vlib_get_next_frame (vm, node, next_index,
                       to_next, n_left_to_next);

  for (i = 0; i < n_to_dequeue; i++)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      svm_fifo_t * f0;          /* $$$ prefetch 1 ahead maybe */
      stream_session_t * s0;
      u32 server_session_index0, server_thread_index0;

      e0 = my_fifo_events[i];
      f0 = e0->fifo;
      server_session_index0 = f0->server_session_index;
      server_thread_index0 = f0->server_thread_index;

      /* $$$ add multiple event queues, per vpp worker thread */
      ASSERT(server_thread_index0 == vm->cpu_index);

      s0 = pool_elt_at_index (ssm->sessions[f0->thread_index],
                              server_session_index0);
      b0 = 0;

      switch (e->type)
        {
        case FIFO_EVENT_SERVER_TX:
          bi0 = my_tx_buffers[buffer_freelist_index];
          buffer_freelist_index--;
          b0 = vlib_get_buffer (vm, bi0);
          VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b0);
          if (PREDICT_FALSE(n_trace > 0)) 
            {
              uri_queue_trace_t *t0;
              vlib_trace_buffer (vm, node, next_index,
                                 b0, /* follow_chain */ 1);
              n_trace--;
              t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
              /* $$$ fill in trace */
            }

          next0 = event_queue_tx_fns [s0->type] (vm, s0, b0);
          n_tx_packets++;
          break;

        default:
          clib_warning ("unhandled event type %d", e->type);
        }

      if (b0)
        {
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
          if (n_left_to_next == 0)
            {
              vlib_put_next_frame (vm, node, next_index, n_left_to_next);
              last_put_next = n_tx_packets;
              vlib_get_next_frame (vm, node, next_index,
                                   to_next, n_left_to_next);
            }
        }
    }
  
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  return n_tx_packets;
}

VLIB_REGISTER_NODE (uri_queue_node) = {
  .function = uri_queue_node_fn,
  .name = "uri_queue",
  .vector_size = sizeof (u32),
  .format_trace = format_uri_queue_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(uri_queue_error_strings),
  .error_strings = uri_queue_error_strings,

  .n_next_nodes = URI_QUEUE_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [URI_QUEUE_NEXT_DROP] = "error-drop",
    [URI_QUEUE_IP4_LOOKUP] = "ip4-lookup",
    [URI_QUEUE_IP6_LOOKUP] = "ip6-lookup",
  },
};

/* Uses stream_server_main_t, currently no init routine */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
