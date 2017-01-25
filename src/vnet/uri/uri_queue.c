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

#include <vnet/uri/uri.h>
#include <vnet/tcp/tcp.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vlibmemory/unix_shared_memory_queue.h>

#include <vnet/ip/udp_packet.h>
#include <vnet/lisp-cp/packets.h>
#include <math.h>

vlib_node_registration_t uri_queue_node;

typedef struct 
{
  u32 session_index;
  u32 server_thread_index;
} uri_queue_trace_t;

/* packet trace format function */
static u8 * format_uri_queue_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  uri_queue_trace_t * t = va_arg (*args, uri_queue_trace_t *);
  
  s = format (s, "URI_QUEUE: session index %d, server thread index %d",
              t->session_index, t->server_thread_index);
  return s;
}

vlib_node_registration_t uri_queue_node;

#define foreach_uri_queue_error                 \
_(TX, "Packets transmitted")                    \
_(TIMER, "Timer events")

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

static u32 session_type_to_next[] =
{
    URI_QUEUE_NEXT_TCP_IP4_OUTPUT,
    URI_QUEUE_NEXT_IP4_LOOKUP,
    URI_QUEUE_NEXT_TCP_IP6_OUTPUT,
    URI_QUEUE_NEXT_IP6_LOOKUP,
};

always_inline int
session_fifo_rx (vlib_main_t *vm, vlib_node_runtime_t *node,
                 session_manager_main_t *smm, fifo_event_t *e0,
                 stream_session_t *s0, u32 my_thread_index, int *n_tx_packets)
{
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 len_to_snd0, len_to_deq0, max_dequeue0, n_bufs;
  u16 snd_mss0;
  u8 *data0;
  u32 next_index, next0, bi0;
  vlib_buffer_t *b0;
  u32 n_frame_bytes, n_frames_per_evt;
  transport_connection_t *tc0;
  transport_proto_vft_t *transport_vft;
  int i;
  u32 *to_next, n_left_to_next;

  next_index = next0 = session_type_to_next[s0->session_type];

  transport_vft = uri_get_transport (s0->session_type);
  tc0 = transport_vft->get_connection (s0->connection_index,
                                       my_thread_index);

  /* Make sure there's something to dequeue */
  max_dequeue0 = svm_fifo_max_dequeue (s0->server_tx_fifo);
  if (max_dequeue0 == 0)
    return 0;

  len_to_snd0 = e0->enqueue_length;

  /* Get the maximum segment size for this transport */
  snd_mss0 = transport_vft->send_mss (tc0);

  /* TODO check if transport is willing to send len_to_snd0
   * bytes (Nagle) */

  n_frame_bytes = snd_mss0 * VLIB_FRAME_SIZE;
  n_frames_per_evt = ceil((double)len_to_snd0 / n_frame_bytes);

  n_bufs = vec_len (smm->tx_buffers[my_thread_index]);

  for (i = 0; i < n_frames_per_evt; i++)
    {
      /* Make sure we have at least one full frame of buffers ready */
      if (PREDICT_FALSE(n_bufs < VLIB_FRAME_SIZE))
        {
          vec_validate(smm->tx_buffers[my_thread_index],
                       n_bufs + VLIB_FRAME_SIZE - 1);
          n_bufs += vlib_buffer_alloc (
              vm, &smm->tx_buffers[my_thread_index][n_bufs],
              VLIB_FRAME_SIZE);

          /* buffer shortage
           * XXX 0.9 because when debugging we might not get a full frame */
          if (PREDICT_FALSE(n_bufs < 0.9 * VLIB_FRAME_SIZE))
            {
              /* Keep track of how much we've dequeued and exit */
              e0->enqueue_length = len_to_snd0;
              return -1;
            }

          _vec_len (smm->tx_buffers[my_thread_index]) = n_bufs;
        }

      /* TODO check tx window is not full */

      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);
      while (len_to_snd0 && n_left_to_next)
        {
          /* Get free buffer */
          n_bufs --;
          bi0 = smm->tx_buffers[my_thread_index][n_bufs];
          _vec_len (smm->tx_buffers[my_thread_index]) = n_bufs;

          b0 = vlib_get_buffer (vm, bi0);
          b0->error = 0;
          b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID
              | VNET_BUFFER_LOCALLY_ORIGINATED;
          b0->current_data = 0;

          /* RX on the local interface. tx in default fib */
          vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
          vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~0;

          /* usual speculation, or the enqueue_x1 macro will barf */
          to_next[0] = bi0;
          to_next += 1;
          n_left_to_next -= 1;

          VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b0);
          if (PREDICT_FALSE(n_trace > 0))
            {
              uri_queue_trace_t *t0;
              vlib_trace_buffer (vm, node, next_index, b0,
                                 1/* follow_chain */);
              vlib_set_trace_count (vm, node, --n_trace);
              t0 = vlib_add_trace (vm, node, b0, sizeof(*t0));
              t0->session_index = s0->session_index;
              t0->server_thread_index = s0->session_thread_index;
            }

          if (1)
            {
              ELOG_TYPE_DECLARE(e) =
                {
                  .format = "evt-dequeue: id %d length %d",
                  .format_args = "i4i4",
                };
              struct { u32 data[2];} * ed;
              ed = ELOG_DATA (&vm->elog_main, e);
              ed->data[0] = e0->event_id;
              ed->data[1] = e0->enqueue_length;
            }

          len_to_deq0 = (len_to_snd0 < snd_mss0) ? len_to_snd0 : snd_mss0;

          /* Make room for headers */
          data0 = vlib_buffer_make_headroom (b0, MAX_HDRS_LEN);

          /* Dequeue the data
           * TODO 1) peek instead of dequeue
           *      2) buffer chains */
          if (svm_fifo_dequeue_nowait2 (s0->server_tx_fifo, 0, len_to_deq0,
                                          data0) < 0)
            goto dequeue_fail;


          b0->current_length = len_to_deq0;

          /* Ask transport to push header */
          transport_vft->push_header (tc0, b0);

          len_to_snd0 -= len_to_deq0;
          *n_tx_packets = *n_tx_packets + 1;

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return 0;

 dequeue_fail:
  /* Can't read from fifo. Store event rx progress, save as partially read,
   * return buff to free list and return  */
  e0->enqueue_length = len_to_snd0;
  vec_add1 (smm->evts_partially_read[my_thread_index], *e0);

  to_next -= 1;
  n_left_to_next += 1;
  _vec_len (smm->tx_buffers[my_thread_index]) += 1;

  clib_warning ("dequeue fail");
  return 0;
}

static uword
uri_queue_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                   vlib_frame_t * frame)
{
  session_manager_main_t *smm = &session_manager_main;
  fifo_event_t *my_fifo_events, *e;
  u32 n_to_dequeue;
  unix_shared_memory_queue_t *q;
  int n_tx_packets = 0;
  u32 my_thread_index = vm->cpu_index;
  int i, rv;

  /*
   *  Update TCP time
   */
  tcp_update_time (vlib_time_now (vm), my_thread_index);

  /*
   * Get vpp queue events
   */
  q = smm->vpp_event_queues[my_thread_index];
  if (PREDICT_FALSE (q == 0))
    return 0;

  /* min number of events we can dequeue without blocking */
  n_to_dequeue = q->cursize;
  if (n_to_dequeue == 0)
    return 0;

  my_fifo_events = smm->fifo_events[my_thread_index];

  ASSERT (vec_len(my_fifo_events) < 100);

  /* See you in the next life, don't be late */
  if (pthread_mutex_trylock (&q->mutex))
    return 0;
  
  //vec_reset_length (my_fifo_events);
  for (i = 0; i < n_to_dequeue; i++)
    {
      vec_add2 (my_fifo_events, e, 1);
      unix_shared_memory_queue_sub_raw (q, (u8 *) e);
    }

  /* The other side of the connection is not polling */
  if (q->cursize < (q->maxsize / 8))
    (void) pthread_cond_broadcast (&q->condvar);
  pthread_mutex_unlock (&q->mutex);

  smm->fifo_events[my_thread_index] = my_fifo_events;

  for (i = 0; i < n_to_dequeue; i++)
    {
      svm_fifo_t * f0;          /* $$$ prefetch 1 ahead maybe */
      stream_session_t * s0;
      u32 server_session_index0, server_thread_index0;
      fifo_event_t *e0;

      e0 = &my_fifo_events[i];
      f0 = e0->fifo;
      server_session_index0 = f0->server_session_index;
      server_thread_index0 = f0->server_thread_index;

      /* $$$ add multiple event queues, per vpp worker thread */
      ASSERT(server_thread_index0 == my_thread_index);

      s0 = pool_elt_at_index(smm->sessions[my_thread_index],
                             server_session_index0);

      ASSERT(s0->session_thread_index == my_thread_index);

      switch (e0->event_type)
        {
        case FIFO_EVENT_SERVER_TX:
          /* Spray packets in per session type frames, since they go to
           * different nodes */
          rv = session_fifo_rx (vm, node, smm, e0, s0, my_thread_index,
                                &n_tx_packets);
          if (rv < 0)
            goto done;

          break;

        default:
          clib_warning ("unhandled event type %d", e0->event_type);
        }
    }

  done:

  /* Couldn't process all events. Probably out of buffers */
  if (PREDICT_FALSE(i < n_to_dequeue))
    {
      fifo_event_t *partially_read = smm->evts_partially_read[my_thread_index];
      vec_add(partially_read, &my_fifo_events[i], n_to_dequeue - i);
      vec_free(my_fifo_events);
      smm->fifo_events[my_thread_index] = partially_read;
      smm->evts_partially_read[my_thread_index] = 0;
    }
  else
    {
      vec_free (smm->fifo_events[my_thread_index]);
      smm->fifo_events[my_thread_index] =
          smm->evts_partially_read[my_thread_index];
      smm->evts_partially_read[my_thread_index] = 0;
    }

  vlib_node_increment_counter (vm, uri_queue_node.index, URI_QUEUE_ERROR_TX,
                               n_tx_packets);

  return n_tx_packets;
}

VLIB_REGISTER_NODE (uri_queue_node) = {
  .function = uri_queue_node_fn,
  .name = "uri-queue",
  .format_trace = format_uri_queue_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  
  .n_errors = ARRAY_LEN(uri_queue_error_strings),
  .error_strings = uri_queue_error_strings,

  .n_next_nodes = URI_QUEUE_N_NEXT,

  /* .state = VLIB_NODE_STATE_DISABLED, enable on-demand? */

  /* edit / add dispositions here */
  .next_nodes = {
    [URI_QUEUE_NEXT_DROP] = "error-drop",
    [URI_QUEUE_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [URI_QUEUE_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [URI_QUEUE_NEXT_TCP_IP4_OUTPUT] = "tcp4-output",
    [URI_QUEUE_NEXT_TCP_IP6_OUTPUT] = "tcp6-output",
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