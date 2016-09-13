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

#include <vppinfra/sparse_vec.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_packet.h>

typedef struct _tcp_input_runtime
{
  /** Sparse vector mapping tcp dst port in network byte order to next index */
  u16 *next_index_by_dst_port;
} tcp_input_runtime_t;

static char *
tcp_error_strings[] =
{
#define tcp_error(n,s) s,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
};

#define foreach_tcp_established_next            \
  _ (DROP, "error-drop")

typedef enum _tcp_established_next
{
#define _(s,n) TCP_ESTABLISHED_NEXT_##s,
  foreach_tcp_established_next
#undef _
  TCP_ESTABLISHED_N_NEXT,
} tcp_established_next_t;

vlib_node_registration_t tcp4_established_node;
vlib_node_registration_t tcp6_established_node;

always_inline uword
tcp46_established_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                          vlib_frame_t * from_frame, int is_ip4)
{
  __attribute__ ((unused)) tcp_input_runtime_t * rt = is_ip4 ?
    (void *) vlib_node_get_runtime_data (vm, tcp4_established_node.index)
    : (void *) vlib_node_get_runtime_data (vm, tcp6_established_node.index);
  __attribute__((unused)) u32 n_left_from, next_index, * from, * to_next;
  __attribute__ ((unused)) word n_no_listener = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 bi0, bi1;
          vlib_buffer_t * b0, * b1;
          tcp_header_t * h0 = 0, * h1 = 0;
          __attribute__ ((unused)) u32 i0, i1, dst_port0, dst_port1;
          __attribute__ ((unused)) u32 advance0, advance1;
          __attribute__ ((unused)) u32 error0, next0, error1, next1;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, LOAD);
            vlib_prefetch_buffer_header (p3, LOAD);

            CLIB_PREFETCH (p2->data, sizeof (h0[0]), LOAD);
            CLIB_PREFETCH (p3->data, sizeof (h1[0]), LOAD);
          }

          bi0 = from[0];
          bi1 = from[1];
          to_next[0] = bi0;
          to_next[1] = bi1;
          from += 2;
          to_next += 2;
          n_left_to_next -= 2;
          n_left_from -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          /* FIXME DO STUFF */
          next0 = next1 = 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, bi1, next0,
                                          next1);
        }
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          __attribute__ ((unused)) tcp_header_t * h0 = 0;
          __attribute__ ((unused)) u32 i0, next0;
          __attribute__ ((unused)) u32 advance0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          /* FIXME DO STUFF */
          next0 = 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

static uword
tcp4_established (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
  return tcp46_established_inline (vm, node, from_frame, 1 /* is_ip4 */);
}

static uword
tcp6_established (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
  return tcp46_established_inline (vm, node, from_frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (tcp4_established_node) = {
  .function = tcp4_established,
  .name = "tcp4-established",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .runtime_data_bytes = sizeof (tcp_input_runtime_t),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_ESTABLISHED_NEXT_##s] = n,
    foreach_tcp_established_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_established_node, tcp4_established)

VLIB_REGISTER_NODE (tcp6_established_node) = {
  .function = tcp6_established,
  .name = "tcp4-established",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .runtime_data_bytes = sizeof (tcp_input_runtime_t),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_ESTABLISHED_NEXT_##s] = n,
    foreach_tcp_established_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_established_node, tcp6_established)

vlib_node_registration_t tcp4_input_node;
vlib_node_registration_t tcp6_input_node;

#define foreach_tcp_input_next                  \
  _ (PUNT, "error-punt")                        \
  _ (DROP, "error-drop")                        \
  _ (ICMP4_ERROR, "ip4-icmp-error")             \
  _ (ICMP6_ERROR, "ip6-icmp-error")

typedef enum _tcp_input_next
{
#define _(s,n) TCP_INPUT_NEXT_##s,
  foreach_tcp_input_next
#undef _
  TCP_INPUT_N_NEXT,
} tcp_input_next_t;

typedef struct
{
  u16 src_port;
  u16 dst_port;
  u8 state;
} tcp_rx_trace_t;

const char *
tcp_fsm_states[] = {
#define _(sym, str) str,
    foreach_tcp_fsm_state
#undef _
};

u8 *
format_tcp_state (u8 * s, va_list * args)
{
  tcp_fsm_states_t *state = va_arg (args, tcp_fsm_states_t *);

  if (state[0] < TCP_N_STATE)
    s = format (s, "%s", tcp_fsm_states[state[0]]);
  else
    s = format (s, "UNKNOWN");

  return s;
}

u8 *
format_tcp_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp_rx_trace_t * t = va_arg (*args, tcp_rx_trace_t *);

  s = format (s, "TCP: src-port %d dst-port %U%s\n",
      clib_net_to_host_u16(t->src_port),
      clib_net_to_host_u16(t->dst_port),
      format_tcp_state, t->state);

  return s;
}

always_inline uword
tcp46_input_inline (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame,
                    int is_ip4)
{
  __attribute__((unused)) u32 n_left_from, next_index, * from, * to_next;
  __attribute__ ((unused)) word n_no_listener = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 bi0, bi1;
          vlib_buffer_t * b0, * b1;
          tcp_header_t * h0 = 0, * h1 = 0;
          __attribute__ ((unused)) u32 i0, i1, dst_port0, dst_port1;
          __attribute__ ((unused)) u32 advance0, advance1;
          __attribute__ ((unused))  u32 error0, next0, error1, next1;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, LOAD);
            vlib_prefetch_buffer_header (p3, LOAD);

            CLIB_PREFETCH (p2->data, sizeof (h0[0]), LOAD);
            CLIB_PREFETCH (p3->data, sizeof (h1[0]), LOAD);
          }

          bi0 = from[0];
          bi1 = from[1];
          to_next[0] = bi0;
          to_next[1] = bi1;
          from += 2;
          to_next += 2;
          n_left_to_next -= 2;
          n_left_from -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          /* FIXME DO STUFF */
          next0 = next1 = 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, bi1, next0,
                                          next1);
        }
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          __attribute__ ((unused)) tcp_header_t * h0 = 0;
          __attribute__ ((unused)) u32 i0, next0;
          __attribute__ ((unused)) u32 advance0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          /* FIXME DO STUFF */
          next0 = 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_error_count(vm, node->node_index, TCP_ERROR_NO_LISTENER, n_no_listener);
  return from_frame->n_vectors;
}

static uword
tcp4_input (vlib_main_t * vm, vlib_node_runtime_t * node,
            vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 1 /* is_ip4 */);
}

static uword
tcp6_input (vlib_main_t * vm, vlib_node_runtime_t * node,
            vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (tcp4_input_node) = {
  .function = tcp4_input,
  .name = "tcp4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_INPUT_NEXT_##s] = n,
    foreach_tcp_input_next
#undef _
  },

  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_input_node, tcp4_input)

VLIB_REGISTER_NODE (tcp6_input_node) = {
  .function = tcp6_input,
  .name = "tcp6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_INPUT_NEXT_##s] = n,
    foreach_tcp_input_next
#undef _
  },

  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_input_node, tcp6_input)

vlib_node_registration_t tcp4_output_node;
vlib_node_registration_t tcp6_output_node;

#define foreach_tcp_output_next                 \
  _ (DROP, "error-drop")                        \
  _ (IP4_LOOKUP, "ip4-lookup")                 \
  _ (IP6_LOOKUP, "ip6-lookup")

typedef enum _tcp_output_next
{
#define _(s,n) TCP_OUTPUT_NEXT_##s,
  foreach_tcp_output_next
#undef _
  TCP_OUTPUT_N_NEXT,
} tcp_output_next_t;

always_inline uword
tcp46_output_inline (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame,
                    int is_ip4)
{
  __attribute__((unused)) u32 n_left_from, next_index, * from, * to_next;
  __attribute__ ((unused)) word n_no_listener = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 bi0, bi1;
          vlib_buffer_t * b0, * b1;
          tcp_header_t * h0 = 0, * h1 = 0;
          __attribute__ ((unused)) u32 i0, i1, dst_port0, dst_port1;
          __attribute__ ((unused)) u32 advance0, advance1;
          __attribute__ ((unused)) u32 error0, next0, error1, next1;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, LOAD);
            vlib_prefetch_buffer_header (p3, LOAD);

            CLIB_PREFETCH (p2->data, sizeof (h0[0]), LOAD);
            CLIB_PREFETCH (p3->data, sizeof (h1[0]), LOAD);
          }

          bi0 = from[0];
          bi1 = from[1];
          to_next[0] = bi0;
          to_next[1] = bi1;
          from += 2;
          to_next += 2;
          n_left_to_next -= 2;
          n_left_from -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          /* FIXME DO STUFF */
          next0 = next1 = 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, bi1, next0,
                                          next1);
        }
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          __attribute__ ((unused)) tcp_header_t * h0 = 0;
          __attribute__ ((unused)) u32 i0, next0;
          __attribute__ ((unused)) u32 advance0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          /* FIXME DO STUFF */
          next0 = 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static uword
tcp4_output (vlib_main_t * vm, vlib_node_runtime_t * node,
            vlib_frame_t * from_frame)
{
  return tcp46_output_inline (vm, node, from_frame, 1 /* is_ip4 */);
}

static uword
tcp6_output (vlib_main_t * vm, vlib_node_runtime_t * node,
            vlib_frame_t * from_frame)
{
  return tcp46_output_inline (vm, node, from_frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (tcp4_output_node) = {
  .function = tcp4_output,
  .name = "tcp4-output",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_OUTPUT_NEXT_##s] = n,
    foreach_tcp_output_next
#undef _
  },

  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_output_node, tcp4_output)

VLIB_REGISTER_NODE (tcp6_output_node) = {
  .function = tcp6_output,
  .name = "tcp6-output",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_OUTPUT_NEXT_##s] = n,
    foreach_tcp_output_next
#undef _
  },

  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_output_node, tcp6_output)


u16 *
tcp_established_get_port_next_index (vlib_main_t * vm, u16 port, u8 is_ip6)
{
  tcp_input_runtime_t * rt;
  rt = vlib_node_get_runtime_data (
      vm, is_ip6 ? tcp6_established_node.index : tcp4_established_node.index);
  return sparse_vec_validate (rt->next_index_by_dst_port,
                              clib_host_to_net_u16 (port));
}

uword
tcp_register_listener (vlib_main_t * vm,
                       tcp_listener_registration_t * r)
{
  tcp_main_t * tm = &tcp_main;
  tcp_listener_t * l;
  u16 * ni;

  {
    clib_error_t * error;
    if ((error = vlib_call_init_function (vm, tcp_lookup_init)))
      clib_error_report (error);
  }

  pool_get_aligned (tm->listener_pool, l, CLIB_CACHE_LINE_BYTES);

  memset (l, 0, sizeof (l[0]));

  l->dst_port = r->port;
  l->valid_local_adjacency_bitmap = 0;
  l->flags = r->flags & (TCP_LISTENER_IP4 | TCP_LISTENER_IP6);

  if (r->flags & TCP_LISTENER_IP4)
    {
      l->next_index[TCP_IP4] = vlib_node_add_next (vm,
                                                   tcp4_established_node.index,
                                                   r->data_node_index);
      /* Setup port to next index sparse vector */
      ni = tcp_established_get_port_next_index (vm, l->dst_port, TCP_IP4);
      ni[0] = l->next_index[TCP_IP4];
    }

  if (r->flags & TCP_LISTENER_IP6)
    {
      l->next_index[TCP_IP6] = vlib_node_add_next (vm,
                                                   tcp6_established_node.index,
                                                   r->data_node_index);
      /* Setup port to next index sparse vector */
      ni = tcp_established_get_port_next_index (vm, l->dst_port, TCP_IP6);
      ni[0] = l->next_index[TCP_IP6];
    }

  tm->listener_index_by_dst_port[clib_host_to_net_u16 (l->dst_port)] = l
      - tm->listener_pool;

  return l - tm->listener_pool;
}

clib_error_t *
tcp_lookup_init (vlib_main_t * vm)
{
  clib_error_t * error = 0;
//  tcp_main_t * tm = vnet_get_tcp_main ();

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  return error;
}

VLIB_INIT_FUNCTION (tcp_lookup_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
