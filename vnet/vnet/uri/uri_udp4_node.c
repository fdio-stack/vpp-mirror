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

vlib_node_registration_t udp4_uri_input_node;

typedef struct 
{
  u32 session;
  u32 disposition
  u32 thread_index;
} udp4_uri_input_trace_t;

/* packet trace format function */
static u8 * format_udp4_uri_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp4_uri_input_trace_t * t = va_arg (*args, udp4_uri_input_trace_t *);
  
  s = format (s, "UDP4_URI_INPUT: session %d, disposition %d, thread %d",
              t->session, t->disposition, t->thread_index);
  return s;
}

vlib_node_registration_t udp4_uri_input_node;

#define foreach_udp4_uri_input_error                            \
_(NO_SESSION, "No session drops")                               \
_(NO_LISTENER, "No listener for dst port drops")                \
_(ENQUEUED, "Packets pushed into rx fifo")                      \
_(NOT_READY, "Session not ready packets")                       \
_(FIFO_FULL, "Packets dropped for lack of rx fifo space")

typedef enum {
#define _(sym,str) UDP4_URI_INPUT_ERROR_##sym,
  foreach_udp4_uri_input_error
#undef _
  UDP4_URI_INPUT_N_ERROR,
} udp4_uri_input_error_t;

static char * udp4_uri_input_error_strings[] = {
#define _(sym,string) string,
  foreach_udp4_uri_input_error
#undef _
};

typedef enum {
  UDP4_URI_INPUT_NEXT_DROP
  UDP4_URI_INPUT_N_NEXT,
} udp4_uri_input_next_t;

static uword
udp4_uri_input_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  udp4_uri_input_next_t next_index;
  stream_server_main_t * ssm = &stream_server_main;
  u32 my_thread_index = vm->cpu_index;
  u8 my_enqueue_epoch;
  u32 * session_indices_to_enqueue;

  my_enqueue_epoch = ++ssm->enqueue_epoch[my_thread_index];

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
          u32 next0 = UDP4_URI_INPUT_NEXT_INTERFACE_OUTPUT;
          u32 next1 = UDP4_URI_INPUT_NEXT_INTERFACE_OUTPUT;
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
                    udp4_uri_input_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    udp4_uri_input_trace_t *t = 
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
          u32 next0 = UDP4_URI_INPUT_NEXT_DROP;
          u32 error0 = UDP_URI_INPUT_ERROR_ENQUEUED;
          udp_header_t * udp0;
          clib_bihash_kv_16_8_t kv0;
          udp4_session_key_t key0;
          ip4_header_t * ip0;
          udp4_session_t * s0;
          svm_fifo_t * f0;
          stream_server_t *ss0;
          u16 udp_len0;
          u16 i0;
          
          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          udp0 = vlib_buffer_get_current (b0);

          /* $$$$ fixme: udp_local doesn't do ip options correctly anyhow */
          ip0 = ((u8 *)udp0) - sizeof (*ip0);
          s0 = 0;

          key0.src.as_u32 = ip0->src.as_u32;
          key0.dst.as_u32 = ip0->dst.as_u32;
          key0.src_port = udp0->src_port;
          key0.dst_port = udp0->dst_port;
          key0.is_tcp = 0;

          kv0.key.as_u64[0] = key0.as_u64[0];
          kv0.key.as_u64[1] = key0.as_u64[1];
          kv0.value = ~0ULL;

          /* look for session */
          clib_bihash_16_8_search_inline (ssm->v4_session_hash, &kv0);

          if (PREDICT_TRUE (kv0.value != ~0ULL))
            {
              s0 = pool_elt_at_index (ssm->sessions_by_thread[my_thread_index],
                                      kv0.value & 0xFFFFFFFFULL);

              ASSERT(s0->
 
              f0 = s0->server_rx_fifo;
              
              if (PREDICT_FALSE(f0->state != UDP_SESSION_STATE_READY))
                {
                  error0 = UDP4_URI_INPUT_NOT_READY
                  goto trace0;
                }

              udp_len0 = clib_net_to_host_u16 (udp0->length);

              if (PREDICT_FALSE(udp->len0 > svm_fifo_max_enqueue (f0)))
                {
                  error0 = UDP4_URI_INPUT_FIFO_FULL;
                  goto trace0;
                }

              svm_fifo_enqueue (f0, 0 /* pid */, udp_len0,
                                (u8 *)(udp0+1));

              b0->error = node->errors[UDP4_URI_INPUT_ENQUEUED];

              /* We need to send an RX event on this fifo, see below */
              if(f0->enqueue_epoch != my_enqueue_epoch)
                {
                  f0->enqueue_epoch = my_enqueue_epoch;
                  vec_add1 (ssm->session_indices_to_enqueue_by_thread
                            [my_thread_index], s0 - ssm->sessions);
                }
            } 
          else
            {
              b0->error = node->errors[UDP4_URI_INPUT_NOT_READY];
              
              /* Find the server */
              i0 = sparse_vec_index (ssm->stream_server_by_dst_port,
                                     udp0->dst_port);
              if (i0 == SPARSE_VEC_INVALID_INDEX)
                {
                  error0 = UDP4_URI_INPUT_NO_LISTENER;
                  goto trace0;
                  
                }
              ss0 = pool_elt_at_index (ssm->servers, i0);

              /* Create a session */
              s0 = v4_stream_session_create (ssm, ss0, &key0, my_thread_index, 
                                             0 /* is_tcp */);
            }

        trace0:
          b0->error = node->errors[error0];

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              udp4_uri_input_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));

              t->session = ~0;
              if (s0)
                t->session s0 - ssm->sessions_by_thread[my_thread_index];
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
    ssm->sessions_indices_to_enqueue_by_thread[my_thread_index];

  for (i = 0; i < vec_len (session_indices_to_enqueue); i++)
    {
      fifo_event_t evt;
      unix_shared_memory_queue * q;
      
      /* Get session */
      s0 = pool_elt_at_index(ssm->sessions_by_thread, 
                             session_indices_to_enqueue[i]);

      /* Get session's server */
      ss0 = pool_elt_at_index (ssm->servers, s0->server_index);

      /* Fabricate event */
      evt.fifo = s0->server_rx_fifo;
      evt.event_type = FIFO_EVENT_SERVER_RX;

      /* Add event to server's event queue */
      q = ss0->queue;

      /* Don't block for lack of space */
      if (PREDICT_TRUE (q->cursize < q->maxsize))
        unix_shared_memory_queue_add (ss0->queue, &evt, 
                                      0 /* do wait for mutex */);
      else
        {
          vlib_node_increment_counter (vm, foo_node.index, 
                                       FOO_ERROR_SWAPPED, pkts_swapped);
        }
    }

  vec_reset_length (ssm->sessions_to_enqueue_by_thread[my_thread_index]);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (udp4_uri_input_node) = {
  .function = udp4_uri_input_node_fn,
  .name = "udp4-uri-input",
  .vector_size = sizeof (u32),
  .format_trace = format_udp4_uri_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(udp4_uri_input_error_strings),
  .error_strings = udp4_uri_input_error_strings,

  .n_next_nodes = UDP4_URI_INPUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [UDP4_URI_INPUT_NEXT_DROP] = "error-drop",
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
