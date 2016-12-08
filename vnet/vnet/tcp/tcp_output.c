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

#include <vnet/tcp/tcp.h>
#include <vnet/lisp-cp/packets.h>

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

static char *
tcp_error_strings[] =
{
#define tcp_error(n,s) s,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
};

typedef struct
{
  u16 src_port;
  u16 dst_port;
  u8 state;
} tcp_tx_trace_t;

u8 *
format_tcp_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "TBD\n");

  return s;
}

/**
 * Sequence number to send.
 * If window has been shrunk our snd_nxt may be outside the window. What
 * sequence number should be used is unclear. This just reproduces what
 * Linux does.
 */
always_inline u32
tcp_actual_snd_sequence (const tcp_session_t *ts)
{
  u32 wnd_end = tcp_snd_wnd_end (ts);
  if (seq_lt (wnd_end, ts->snd_nxt))
    return ts->snd_nxt;
  else
    return wnd_end;
}

void
tcp_options_write (u8 *data, tcp_options_t * opts)
{
  u32 opts_len = 0;

  if (opts->mss_flag)
    {
      *data++ = TCP_OPTION_MSS;
      *data++ = TCP_OPTION_LEN_MSS;
      *data = clib_host_to_net_u16 (opts->mss);
      data += TCP_OPTION_LEN_MSS;
      opts_len += TCP_OPTION_LEN_MSS;
    }

  if (opts->tstamp_flag)
    {
      *data++ = TCP_OPTION_TIMESTAMP;
      *data++ = TCP_OPTION_LEN_TIMESTAMP;
      *data = clib_host_to_net_u32 (opts->tsval);
      data += sizeof (opts->tsval);
      *data = clib_host_to_net_u32 (opts->tsecr);
      data += sizeof (opts->tsecr);
      opts_len += TCP_OPTION_LEN_TIMESTAMP;
    }

  if (opts->wscale_flag)
    {
      *data++ = TCP_OPTION_WINDOW_SCALE;
      *data++ = TCP_OPTION_LEN_WINDOW_SCALE;
      *data++ = opts->wscale;
      opts_len += TCP_OPTION_LEN_WINDOW_SCALE;
    }

  /* Terminate TCP options */
  if (opts_len % 4)
    {
      *data++ = TCP_OPTION_EOL;
      opts_len += TCP_OPTION_LEN_EOL;
    }

  /* Pad with zeroes to a u32 boundary */
  while (opts_len % 4)
    {
      *data++ = TCP_OPTION_NOOP;
      opts_len += TCP_OPTION_LEN_NOOP;
    }
}

always_inline int
tcp_make_syn_or_synack_options (tcp_session_t *ts, tcp_options_t *opts)
{
  u8 len = 0;

  opts->mss_flag = 1;
  opts->mss = 1400; /*XXX discover that */
  len += TCP_OPTION_LEN_MSS;

  if (ts->opt.wscale_flag)
    {
      opts->wscale_flag = 1;
      opts->wscale = ts->opt.wscale_snd;
      len += TCP_OPTION_LEN_WINDOW_SCALE;
    }

  if (ts->opt.tstamp_flag)
    {
      opts->tstamp_flag = 1;
      opts->tsval = tcp_time_now ();
      opts->tsecr = ts->opt.tsval_recent;
      len += TCP_OPTION_LEN_TIMESTAMP;
    }

  return len;
}

always_inline int
tcp_make_established_options (tcp_session_t *ts, tcp_options_t *opts)
{
  u8 len = 0;

  if (ts->opt.tstamp_flag)
    {
      opts->tstamp_flag = 1;
      opts->tsval = tcp_time_now ();
      opts->tsecr = ts->opt.tsval_recent;
      len += TCP_OPTION_LEN_TIMESTAMP;
    }
  return len;
}

/**
 * Queue ack for sending
 */
void
tcp_send_ack (tcp_session_t *ts, u8 is_ip4)
{
  vlib_buffer_t *b;
  vlib_frame_t *f;
  u32 bi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u32 *to_next, next_index;
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  u8 tcp_opts_len, tcp_hdr_opts_len;
  tcp_header_t *th;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("Can't allocate buffer!");
      return;
    }

  b = vlib_get_buffer (vm, bi);

  /* leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  /* Make and write options */
  tcp_opts_len = tcp_make_established_options (ts, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  /* Window in syn and syn|ack segments is not scaled */
  th = pkt_push_tcp (vm, b, ts->s_lcl_port, ts->s_rmt_port,
                     tcp_actual_snd_sequence (ts), ts->rcv_nxt,
                     tcp_hdr_opts_len, TCP_FLAG_ACK,
                     clib_min(ts->rcv_wnd, 65535U));

  tcp_options_write ((u8 *)(th + 1), snd_opts);
  ts->rcv_las = ts->rcv_nxt;

  vnet_buffer (b)->tcp.session_index = ts->s_t_index;
  vnet_buffer (b)->tcp.flags = TCP_FLAG_ACK;

  /* Get frame to the right node
   * XXX should we queue acks and deliver as burst? */
  next_index = is_ip4 ? tcp4_output_node.index : tcp6_output_node.index;
  f = vlib_get_frame_to_node (vm, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);
}

/**
 * Queue synack for sending
 */
void
tcp_send_synack (tcp_session_t *ts, u8 is_ip4)
{
  vlib_buffer_t *b;
  vlib_frame_t *f;
  u32 bi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u32 *to_next, next_index;
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  u8 tcp_opts_len, tcp_hdr_opts_len;
  tcp_header_t *th;
  u32 time_now;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("Can't allocate buffer!");
      return;
    }

  b = vlib_get_buffer (vm, bi);

  /* Leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  /* Set random initial sequence */
  time_now = tcp_time_now();
  ts->iss = random_u32 (&time_now);

  /* Make and write options */
  tcp_opts_len = tcp_make_syn_or_synack_options (ts, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = pkt_push_tcp (vm, b, ts->s_lcl_port, ts->s_rmt_port, ts->iss,
                     ts->rcv_nxt, tcp_hdr_opts_len, TCP_FLAG_SYN | TCP_FLAG_ACK,
                     clib_min(ts->rcv_wnd, 65535U));


  tcp_options_write ((u8 *)(th + 1), snd_opts);
  ts->rcv_las = ts->rcv_nxt;

  vnet_buffer (b)->tcp.session_index = ts->s_t_index;
  vnet_buffer (b)->tcp.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

  /* Get frame to the right node
   * XXX should we queue acks and deliver as burst? */
  next_index = is_ip4 ? tcp4_output_node.index : tcp6_output_node.index;
  f = vlib_get_frame_to_node (vm, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);
}

void
tcp_send_dupack (tcp_session_t *ts, u8 is_ip4)
{
  clib_warning ("unimplemented");
}

void
tcp_send_challange_ack (tcp_session_t *ts, u8 is_ip4)
{
  clib_warning ("unimplemented");
}

/**
 *  Send reset
 */
void
tcp_send_reset (vlib_buffer_t *pkt, u8 is_ip4)
{
  vlib_buffer_t *b;
  vlib_frame_t *f;
  u32 bi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u32 *to_next, next_index;
  u8 tcp_hdr_len, flags = 0;
  tcp_header_t *th, * pkt_th;
  u32 seq, ack;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("Can't allocate buffer!");
      return;
    }

  b = vlib_get_buffer (vm, bi);

  /* Leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  /* Make and write options */
  tcp_hdr_len = sizeof (tcp_header_t);

  pkt_th = vlib_buffer_get_current (pkt);
  if (tcp_ack (pkt_th))
    {
     flags = TCP_FLAG_RST;
     seq = pkt_th->ack_number;
     ack = 0;
    }
  else
    {
      flags = TCP_FLAG_RST | TCP_FLAG_ACK;
      seq = 0;
      ack = clib_host_to_net_u32(vnet_buffer (pkt)->tcp.end_seq);
    }

  th = pkt_push_tcp_net_order (vm, b, pkt_th->dst_port, pkt_th->src_port, seq,
                               ack, tcp_hdr_len, flags, 0);

  if (is_ip4)
    {
      ip4_header_t * ih, *pkt_ih;

      /* XXX options */
      pkt_ih = (ip4_header_t *)((u8 *)th - sizeof(ip4_header_t));

      ASSERT ((pkt_ih->ip_version_and_header_length & 0xF0) == 0x40);

      ih = pkt_push_ipv4 (vm, b, &pkt_ih->dst_address, &pkt_ih->src_address,
                          IP_PROTOCOL_TCP);
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ih);
    }
  else
    {
      ip6_header_t * ih, *pkt_ih;
      int bogus = ~0;
      /* XXX options */
      pkt_ih = (ip6_header_t *)((u8 *)th - sizeof(ip6_header_t));

      ASSERT ((pkt_ih->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60);
      ih = pkt_push_ipv6 (vm, b, &pkt_ih->dst_address, &pkt_ih->dst_address,
                          IP_PROTOCOL_TCP);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ih, &bogus);
      ASSERT(!bogus);
    }

  /* Send to IP lookup */
  next_index = is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
  f = vlib_get_frame_to_node (vm, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);
}

always_inline uword
tcp46_output_inline (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame,
                    int is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  u32 my_thread_index = vm->cpu_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          tcp_session_t *ts0;
          tcp_header_t *th0;
          u32 error0 = TCP_ERROR_NO_LISTENER, next0 = TCP_OUTPUT_NEXT_DROP;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          ts0 = tcp_session_get (vnet_buffer(b0)->tcp.session_index,
                                 my_thread_index);
          th0 = vlib_buffer_get_current (b0);

          if (is_ip4)
            {
              ip4_header_t * ih0;
              ih0 = pkt_push_ipv4 (vm, b0, &ts0->s_lcl_ip4, &ts0->s_rmt_ip4,
                                   IP_PROTOCOL_TCP);
              th0->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ih0);
            }
          else
            {
              ip6_header_t * ih0;
              int bogus = ~0;

              ih0 = pkt_push_ipv6 (vm, b0, &ts0->s_lcl_ip6, &ts0->s_rmt_ip6,
                                   IP_PROTOCOL_TCP);
              th0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ih0,
                                                                 &bogus);
              ASSERT (!bogus);
            }

          /* set fib index to default and lookup node */
          /* XXX network virtualization (vrf/vni)*/
          vnet_buffer (b0)->sw_if_index[VLIB_TX] = 0;
          next0 = is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;

          b0->error = node->errors[error0];
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
  .format_trace = format_tcp_tx_trace,
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
  .format_trace = format_tcp_tx_trace,
};

u16
tcp_mss_to_advertise (tcp_session_t *ts)
{
  /* TODO cache mss and consider PMTU discovery */

  return ts->opt.mss;
}

/**
 * Compute and return window to advertise, scaled as per RFC1323
 */
u32
tcp_window_to_advertise (tcp_session_t *ts, u32 my_thread_index)
{
  stream_session_t *s;
  u32 available_space, wnd;

  s = stream_session_get (ts->s_s_index, my_thread_index);

  available_space = svm_fifo_max_enqueue (s->server_rx_fifo);
  wnd = clib_min (available_space, 65535U << ts->opt.wscale_snd);
  ts->rcv_wnd = wnd;

  return wnd >> ts->opt.wscale_snd;
}

/**
 * Read as much data as possible from the tx fifo, build a tcp packet and
 * ask that it be sent to tcp-output
 */
u32
tcp_uri_tx_packetize_inline (vlib_main_t *vm, stream_session_t *s,
                             vlib_buffer_t *b, u8 is_ip4)
{
  tcp_main_t * tm = vnet_get_tcp_main ();
  u32 max_dequeue, len_to_dequeue, advertise_wnd;
  u32 my_thread_index = vm->cpu_index;
  svm_fifo_t * f;
  u8 * data;
  u16 snd_mss;
  tcp_session_t *ts;
  u8 tcp_opts_len, tcp_hdr_opts_len;
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;

  ASSERT(s->session_thread_index == my_thread_index);

  ts = pool_elt_at_index(tm->sessions[my_thread_index],
                         s->transport_session_index);

  f = s->server_tx_fifo;

  /* Make room for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  data = vlib_buffer_get_current (b);

  /* TODO peek instead of dequeue since some data may not have been acked */
  /* TODO Nagle */

  /* Dequeue a bunch of data into the packet buffer */
  max_dequeue = svm_fifo_max_dequeue (f);
  if (max_dequeue == 0)
    {
      /* $$$$ set b0->error = node->errors[nil dequeue] */
      return URI_QUEUE_NEXT_DROP;
    }

  /* Get the maximum segment size we're willing to accept */
  snd_mss = tcp_mss_to_advertise (ts);

  /* Dequeue the actual data */
  len_to_dequeue = max_dequeue < snd_mss ? max_dequeue : snd_mss;
  svm_fifo_dequeue (f, 0, len_to_dequeue, data);

  /* Make and write options */
  tcp_opts_len = tcp_make_established_options (ts, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  advertise_wnd = tcp_window_to_advertise (ts, my_thread_index);

  pkt_push_tcp (vm, b, ts->s_lcl_port, ts->s_rmt_port,
                tcp_actual_snd_sequence (ts), ts->rcv_nxt, tcp_hdr_opts_len,
                TCP_FLAG_ACK, advertise_wnd);

  if (is_ip4)
    return URI_QUEUE_NEXT_TCP_IP4_OUTPUT;
  else
    return URI_QUEUE_NEXT_TCP_IP6_OUTPUT;
}

u32
tcp_uri_tx_packetize_ip4 (vlib_main_t *vm, stream_session_t *s,
                             vlib_buffer_t *b)
{
  return tcp_uri_tx_packetize_inline (vm, s, b, 1);
}

u32
tcp_uri_tx_packetize_ip6 (vlib_main_t *vm, stream_session_t *s,
                             vlib_buffer_t *b)
{
  return tcp_uri_tx_packetize_inline (vm, s, b, 0);
}



VLIB_NODE_FUNCTION_MULTIARCH (tcp6_output_node, tcp6_output)
