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
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vlibmemory/api.h>
#include <vnet/uri/uri.h>
#include <vnet/tcp/tcp.h>

typedef struct 
{
  u32 session;
  u32 disposition;
  u32 thread_index;
} tcp4_uri_input_trace_t;

/* packet trace format function */
static u8 * format_tcp4_uri_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp4_uri_input_trace_t * t = va_arg (*args, tcp4_uri_input_trace_t *);
  
  s = format (s, "TCP4_URI_INPUT: session %d, disposition %d, thread %d",
              t->session, t->disposition, t->thread_index);
  return s;
}

#define foreach_tcp4_uri_input_error                                    \
_(NO_SESSION, "No session drops")                                       \
_(NO_LISTENER, "No listener for dst port drops")                        \
_(ENQUEUED, "Packets pushed into rx fifo")                              \
_(NOT_READY, "Session not ready packets")                               \
_(FIFO_FULL, "Packets dropped for lack of rx fifo space")               \
_(EVENT_FIFO_FULL, "Events not sent for lack of event fifo space")      \
_(API_QUEUE_FULL, "Sessions not created for lack of API queue space")

typedef enum {
#define _(sym,str) TCP4_URI_INPUT_ERROR_##sym,
  foreach_tcp4_uri_input_error
#undef _
  TCP4_URI_INPUT_N_ERROR,
} tcp4_uri_input_error_t;

static char * tcp4_uri_input_error_strings[] = {
#define _(sym,string) string,
  foreach_tcp4_uri_input_error
#undef _
};

typedef enum {
  TCP4_URI_INPUT_NEXT_DROP,
  TCP4_URI_INPUT_N_NEXT,
} tcp4_uri_input_next_t;

void
uri_tcp_session_delete (transport_session_t *s)
{
  tcp_session_t * us;
  us = (tcp_session_t *) s;
  clib_mem_free(us);
}

static transport_session_vft_t tcp4_session_vft = {
    .create = 0,
    .delete = uri_tcp_session_delete
};

static uword
tcp4_uri_input_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  tcp4_uri_input_next_t next_index;
  stream_server_main_t * ssm = &stream_server_main;
  u32 my_thread_index = vm->cpu_index;
  u8 my_enqueue_epoch;
  u32 * session_indices_to_enqueue;
  static u32 serial_number;
  int i;

  my_enqueue_epoch = ++ssm->current_enqueue_epoch[my_thread_index];

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

#if 0
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 next0 = TCP4_URI_INPUT_NEXT_INTERFACE_OUTPUT;
          u32 next1 = TCP4_URI_INPUT_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0, sw_if_index1;
          u8 tmp0[6], tmp1[6];
          ethernet_header_t *en0, *en1;
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;
            
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
            
	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

          /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          /* $$$$$ Dual loop: process 2 x packets here $$$$$ */
          ASSERT (b0->current_data == 0);
          ASSERT (b1->current_data == 0);
          
          en0 = vlib_buffer_get_current (b0);
          en1 = vlib_buffer_get_current (b1);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          /* Send pkt back out the RX interface */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_if_index0;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = sw_if_index1;

          pkts_swapped += 2;
          /* $$$$$ End of processing 2 x packets $$$$$ */

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                  tcp4_uri_input_trace_t *t =
                    vlib_add_trace (vm, node, b0, sizeof (*t));
                  t->sw_if_index = sw_if_index0;
                  t->next_index = next0;
                }
              if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                {
                  tcp4_uri_input_trace_t *t =
                    vlib_add_trace (vm, node, b1, sizeof (*t));
                  t->sw_if_index = sw_if_index1;
                  t->next_index = next1;
                }
            }
            
          /* verify speculative enqueues, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
        }
#endif /* dual loop off */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0 = TCP4_URI_INPUT_NEXT_DROP;
          u32 error0 = TCP4_URI_INPUT_ERROR_ENQUEUED;
          tcp_header_t * tcp0;
          ip4_header_t * ip0;
          stream_session_t * s0;
          svm_fifo_t * f0;
          u16 tcp_h_len0, tcp_data_len0;
          u8 * data0;
          u64 value;
          
          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /* udp_local hands us a pointer to the udp data */

          data0 = vlib_buffer_get_current (b0);
          tcp0 = (tcp_header_t *)(data0 - sizeof (*tcp0));

          /* $$$$ fixme: udp_local doesn't do ip options correctly anyhow */
          ip0 = (ip4_header_t *) (((u8 *)tcp0) - sizeof (*ip0));
          s0 = 0;

          /* look session */
          value = stream_session_lookup4 (&ip0->dst_address, &ip0->src_address,
                                          tcp0->dst_port, tcp0->src_port,
                                          SESSION_TYPE_IP4_TCP);

          if (PREDICT_TRUE (value != ~0ULL))
            {
              s0 = pool_elt_at_index (ssm->sessions[my_thread_index],
                                      value & 0xFFFFFFFFULL);
 
              ASSERT ((u32)(value >> 32) == my_thread_index);

              f0 = s0->server_rx_fifo;
              
              if (PREDICT_FALSE(s0->session_state != SESSION_STATE_READY))
                {
                  error0 = TCP4_URI_INPUT_ERROR_NOT_READY;
                  goto trace0;
                }

              tcp_h_len0 = tcp_header_bytes (tcp0);
              tcp_data_len0 = clib_net_to_host_u16 (ip0->length)
                  - ip4_header_bytes (ip0) - tcp_h_len0;

              if (PREDICT_FALSE(tcp_data_len0 > svm_fifo_max_enqueue (f0)))
                {
                  error0 = TCP4_URI_INPUT_ERROR_FIFO_FULL;
                  goto trace0;
                }

              svm_fifo_enqueue_nowait2 (f0, 0 /* pid */, tcp_data_len0,
                                        (u8 *) data0);

              b0->error = node->errors[TCP4_URI_INPUT_ERROR_ENQUEUED];

              /* We need to send an RX event on this fifo */
              if(s0->enqueue_epoch != my_enqueue_epoch)
              {
                  s0->enqueue_epoch = my_enqueue_epoch;
                  
                  vec_add1 (ssm->session_indices_to_enqueue_by_thread
                            [my_thread_index], 
                            s0 - ssm->sessions[my_thread_index]);
              }
            }
          else
            {
              tcp_session_t *s;

              b0->error = node->errors[TCP4_URI_INPUT_ERROR_NOT_READY];
              
              s = clib_mem_alloc(sizeof(*s));
              s->s_vft = &tcp4_session_vft;

              error0 = stream_session_create (&s->session, my_thread_index,
                                              SESSION_TYPE_IP4_TCP);
            }

        trace0:
          b0->error = node->errors[error0];

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              tcp4_uri_input_trace_t *t =
                vlib_add_trace (vm, node, b0, sizeof (*t));

              t->session = ~0;
              if (s0)
                t->session = s0 - ssm->sessions[my_thread_index];
              t->disposition = error0;
              t->thread_index = my_thread_index;
            }

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  
  /* Send enqueue events */
  
  session_indices_to_enqueue = 
    ssm->session_indices_to_enqueue_by_thread[my_thread_index];

  for (i = 0; i < vec_len (session_indices_to_enqueue); i++)
    {
      fifo_event_t evt;
      unix_shared_memory_queue_t * q;
      stream_session_t * s0;
      stream_server_t *ss0;
      
      /* Get session */
      s0 = pool_elt_at_index(ssm->sessions[my_thread_index], 
                             session_indices_to_enqueue[i]);
      
      /* Get session's server */
      ss0 = pool_elt_at_index (ssm->servers, s0->server_index);
      
      /* Fabricate event */
      evt.fifo = s0->server_rx_fifo;
      evt.event_type = FIFO_EVENT_SERVER_RX;
      evt.event_id = serial_number++;
      evt.enqueue_length = svm_fifo_max_dequeue (s0->server_rx_fifo);

      /* Add event to server's event queue */
      q = ss0->event_queue;
      
      /* Don't block for lack of space */
      if (PREDICT_TRUE (q->cursize < q->maxsize))
        unix_shared_memory_queue_add (ss0->event_queue, (u8 *)&evt, 
                                      0 /* do wait for mutex */);
      else
        {
          vlib_node_increment_counter (vm, tcp4_uri_input_node.index,
                                       TCP4_URI_INPUT_ERROR_FIFO_FULL, 1);
        }
      if (1)
        {
          ELOG_TYPE_DECLARE(e) = 
            {
              .format = "evt-enqueue: id %d length %d",
              .format_args = "i4i4",
            };
          struct { u32 data[2];} * ed;
          ed = ELOG_DATA (&vlib_global_main.elog_main, e);
          ed->data[0] = evt.event_id;
          ed->data[1] = evt.enqueue_length;
        }
    }

  vec_reset_length (session_indices_to_enqueue);

  ssm->session_indices_to_enqueue_by_thread[my_thread_index] =
    session_indices_to_enqueue;

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (tcp4_uri_input_node) = {
  .function = tcp4_uri_input_node_fn,
  .name = "tcp4-uri-input",
  .vector_size = sizeof (u32),
  .format_trace = format_tcp4_uri_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(tcp4_uri_input_error_strings),
  .error_strings = tcp4_uri_input_error_strings,

  .n_next_nodes = TCP4_URI_INPUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [TCP4_URI_INPUT_NEXT_DROP] = "error-drop",
  },
};

typedef struct
{
  u32 session;
  u32 disposition;
  u32 thread_index;
} tcp6_uri_input_trace_t;

/* packet trace format function */
static u8 * format_tcp6_uri_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp6_uri_input_trace_t * t = va_arg (*args, tcp6_uri_input_trace_t *);

  s = format (s, "TCP6_URI_INPUT: session %d, disposition %d, thread %d",
              t->session, t->disposition, t->thread_index);
  return s;
}

#define foreach_tcp6_uri_input_error                                    \
_(NO_SESSION, "No session drops")                                       \
_(NO_LISTENER, "No listener for dst port drops")                        \
_(ENQUEUED, "Packets pushed into rx fifo")                              \
_(NOT_READY, "Session not ready packets")                               \
_(FIFO_FULL, "Packets dropped for lack of rx fifo space")               \
_(EVENT_FIFO_FULL, "Events not sent for lack of event fifo space")      \
_(API_QUEUE_FULL, "Sessions not created for lack of API queue space")

typedef enum {
#define _(sym,str) TCP6_URI_INPUT_ERROR_##sym,
  foreach_tcp6_uri_input_error
#undef _
  TCP6_URI_INPUT_N_ERROR,
} tcp6_uri_input_error_t;

static char * tcp6_uri_input_error_strings[] = {
#define _(sym,string) string,
  foreach_tcp6_uri_input_error
#undef _
};

typedef enum {
  TCP6_URI_INPUT_NEXT_DROP,
  TCP6_URI_INPUT_N_NEXT,
} tcp6_uri_input_next_t;

static uword
tcp6_uri_input_node_fn (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  tcp6_uri_input_next_t next_index;
  stream_server_main_t * ssm = &stream_server_main;
  u32 my_thread_index = vm->cpu_index;
  u8 my_enqueue_epoch;
  u32 * session_indices_to_enqueue;
  static u32 serial_number;
  int i;

  my_enqueue_epoch = ++ssm->current_enqueue_epoch[my_thread_index];

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

#if 0
      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 next0 = TCP6_URI_INPUT_NEXT_INTERFACE_OUTPUT;
          u32 next1 = TCP6_URI_INPUT_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0, sw_if_index1;
          u8 tmp0[6], tmp1[6];
          ethernet_header_t *en0, *en1;
          u32 bi0, bi1;
          vlib_buffer_t * b0, * b1;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, LOAD);
            vlib_prefetch_buffer_header (p3, LOAD);

            CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
            CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
          }

          /* speculatively enqueue b0 and b1 to the current next frame */
          to_next[0] = bi0 = from[0];
          to_next[1] = bi1 = from[1];
          from += 2;
          to_next += 2;
          n_left_from -= 2;
          n_left_to_next -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          /* $$$$$ Dual loop: process 2 x packets here $$$$$ */
          ASSERT (b0->current_data == 0);
          ASSERT (b1->current_data == 0);

          en0 = vlib_buffer_get_current (b0);
          en1 = vlib_buffer_get_current (b1);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          /* Send pkt back out the RX interface */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_if_index0;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = sw_if_index1;

          pkts_swapped += 2;
          /* $$$$$ End of processing 2 x packets $$$$$ */

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED)
                {
                  tcp6_uri_input_trace_t *t =
                    vlib_add_trace (vm, node, b0, sizeof (*t));
                  t->sw_if_index = sw_if_index0;
                  t->next_index = next0;
                }
              if (b1->flags & VLIB_BUFFER_IS_TRACED)
                {
                  tcp6_uri_input_trace_t *t =
                    vlib_add_trace (vm, node, b1, sizeof (*t));
                  t->sw_if_index = sw_if_index1;
                  t->next_index = next1;
                }
            }

          /* verify speculative enqueues, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
        }
#endif /* dual loop off */

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0 = TCP6_URI_INPUT_NEXT_DROP;
          u32 error0 = TCP6_URI_INPUT_ERROR_ENQUEUED;
          tcp_header_t * tcp0;
          ip6_header_t * ip0;
          stream_session_t * s0;
          svm_fifo_t * f0;
//          stream_server_t *ss0;
          u16 tcp_h_len0, tcp_data_len0;
//          u16 i0;
          u8 * data0;
          u64 value;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          /* tcp_local hands us a pointer to the tcp data */

          data0 = vlib_buffer_get_current (b0);
          tcp0 = (tcp_header_t *)(data0 - sizeof (*tcp0));

          /* $$$$ fixme: tcp_local doesn't do ip options correctly anyhow */
          ip0 = (ip6_header_t *) (((u8 *)tcp0) - sizeof (*ip0));
          s0 = 0;

          /* look session */
          value = stream_session_lookup6 (&ip0->dst_address, &ip0->src_address,
                                          tcp0->dst_port, tcp0->src_port,
                                          SESSION_TYPE_IP6_TCP);

          if (PREDICT_TRUE (value != ~0ULL))
            {
              s0 = pool_elt_at_index (ssm->sessions[my_thread_index],
                                      value & 0xFFFFFFFFULL);

              ASSERT ((u32)(value >> 32) == my_thread_index);

              f0 = s0->server_rx_fifo;

              if (PREDICT_FALSE(s0->session_state != SESSION_STATE_READY))
                {
                  error0 = TCP6_URI_INPUT_ERROR_NOT_READY;
                  goto trace0;
                }

              tcp_h_len0 = tcp_header_bytes (tcp0);
              tcp_data_len0 = clib_net_to_host_u16 (ip0->payload_length)
                  - tcp_h_len0;

              if (PREDICT_FALSE(tcp_data_len0 > svm_fifo_max_enqueue (f0)))
                {
                  error0 = TCP6_URI_INPUT_ERROR_FIFO_FULL;
                  goto trace0;
                }

              svm_fifo_enqueue_nowait2 (f0, 0 /* pid */,
                                        tcp_data_len0,
                                        (u8 *)(tcp0+1));

              b0->error = node->errors[TCP6_URI_INPUT_ERROR_ENQUEUED];

              /* We need to send an RX event on this fifo */
              if(s0->enqueue_epoch != my_enqueue_epoch)
              {
                  s0->enqueue_epoch = my_enqueue_epoch;

                  vec_add1 (ssm->session_indices_to_enqueue_by_thread
                            [my_thread_index],
                            s0 - ssm->sessions[my_thread_index]);
              }
            }
          else
            {
              tcp_session_t *s;

              b0->error = node->errors[TCP6_URI_INPUT_ERROR_NOT_READY];

              s = clib_mem_alloc(sizeof(*s));

              error0 = stream_session_create (&s->session, my_thread_index,
                                              SESSION_TYPE_IP6_TCP);
            }

        trace0:
          b0->error = node->errors[error0];

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              tcp6_uri_input_trace_t *t =
                vlib_add_trace (vm, node, b0, sizeof (*t));

              t->session = ~0;
              if (s0)
                t->session = s0 - ssm->sessions[my_thread_index];
              t->disposition = error0;
              t->thread_index = my_thread_index;
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Send enqueue events */

  session_indices_to_enqueue =
    ssm->session_indices_to_enqueue_by_thread[my_thread_index];

  for (i = 0; i < vec_len (session_indices_to_enqueue); i++)
    {
      fifo_event_t evt;
      unix_shared_memory_queue_t * q;
      stream_session_t * s0;
      stream_server_t *ss0;

      /* Get session */
      s0 = pool_elt_at_index(ssm->sessions[my_thread_index],
                             session_indices_to_enqueue[i]);

      /* Get session's server */
      ss0 = pool_elt_at_index (ssm->servers, s0->server_index);

      /* Fabricate event */
      evt.fifo = s0->server_rx_fifo;
      evt.event_type = FIFO_EVENT_SERVER_RX;
      evt.event_id = serial_number++;
      evt.enqueue_length = svm_fifo_max_dequeue (s0->server_rx_fifo);

      /* Add event to server's event queue */
      q = ss0->event_queue;

      /* Don't block for lack of space */
      if (PREDICT_TRUE (q->cursize < q->maxsize))
        unix_shared_memory_queue_add (ss0->event_queue, (u8 *)&evt,
                                      0 /* do wait for mutex */);
      else
        {
          vlib_node_increment_counter (vm, tcp6_uri_input_node.index,
                                       TCP6_URI_INPUT_ERROR_FIFO_FULL, 1);
        }
      if (1)
        {
          ELOG_TYPE_DECLARE(e) =
            {
              .format = "evt-enqueue: id %d length %d",
              .format_args = "i4i4",
            };
          struct { u32 data[2];} * ed;
          ed = ELOG_DATA (&vlib_global_main.elog_main, e);
          ed->data[0] = evt.event_id;
          ed->data[1] = evt.enqueue_length;
        }
    }

  vec_reset_length (session_indices_to_enqueue);

  ssm->session_indices_to_enqueue_by_thread[my_thread_index] =
    session_indices_to_enqueue;

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (tcp6_uri_input_node) = {
  .function = tcp6_uri_input_node_fn,
  .name = "tcp6-uri-input",
  .vector_size = sizeof (u32),
  .format_trace = format_tcp6_uri_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(tcp6_uri_input_error_strings),
  .error_strings = tcp6_uri_input_error_strings,

  .n_next_nodes = TCP6_URI_INPUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [TCP6_URI_INPUT_NEXT_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
