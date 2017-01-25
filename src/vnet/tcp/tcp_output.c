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

u16 dummy_mtu = 400;

u8 *
format_tcp_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "TBD\n");

  return s;
}

u16
tcp_snd_mss (tcp_connection_t *tc)
{
  u16 snd_mss;

  /* TODO find our iface MTU */
  snd_mss = dummy_mtu;

  /* TODO cache mss and consider PMTU discovery */
  snd_mss = tc->opt.mss < snd_mss ? tc->opt.mss : snd_mss;

  return snd_mss;
}

static u8
tcp_window_compute_scale (u32 available_space)
{
  u8 wnd_scale = 0;
  while (wnd_scale < TCP_MAX_WND_SCALE
      && (available_space >> wnd_scale) > TCP_MAX_WND)
    wnd_scale++;
  return wnd_scale;
}
/**
 * Compute initial window and scale factor. As per RFC1323, window field in
 * SYN and SYN-ACK segments is never scaled.
 */
u32
tcp_initial_window_to_advertise (tcp_connection_t *tc)
{
  stream_session_t *s;
  u32 available_space;

  s = stream_session_get (tc->c_s_index, tc->c_thread_index);

  /* XXX Assuming here that we got max fifo size */
  available_space = svm_fifo_max_enqueue (s->server_rx_fifo);
  tc->rcv_wscale = tcp_window_compute_scale (available_space);
  tc->rcv_wnd = clib_min (available_space, TCP_MAX_WND << tc->rcv_wscale);

  return clib_min (tc->rcv_wnd, TCP_MAX_WND);
}

/**
 * Compute and return window to advertise, scaled as per RFC1323
 */
u32
tcp_window_to_advertise (tcp_connection_t *tc)
{
  stream_session_t *s;
  u32 available_space, wnd, scaled_space;

  s = stream_session_get (tc->c_s_index, tc->c_thread_index);

  available_space = svm_fifo_max_enqueue (s->server_rx_fifo);
  scaled_space = available_space >> tc->rcv_wscale;

  /* Need to update scale */
  if (PREDICT_FALSE((scaled_space == 0 && available_space != 0))
      || (scaled_space >= TCP_MAX_WND))
    tc->rcv_wscale = tcp_window_compute_scale (available_space);

  wnd = clib_min (available_space, TCP_MAX_WND << tc->rcv_wscale);
  tc->rcv_wnd = wnd;

  return wnd >> tc->rcv_wscale;
}

/**
 * Write TCP options to segment.
 *
 * It involves some magic padding of options as observed for bsd.
 */
u32
tcp_options_write (u8 *data, tcp_options_t * opts)
{
  u32 opts_len = 0;
  u32 buf, seq_len = 4;

  if (tcp_opts_mss(opts))
    {
      *data++ = TCP_OPTION_MSS;
      *data++ = TCP_OPTION_LEN_MSS;
      buf = clib_host_to_net_u16 (opts->mss);
      clib_memcpy (data, &buf, sizeof (opts->mss));
      data += sizeof (opts->mss);
      opts_len += TCP_OPTION_LEN_MSS;
    }

  if (tcp_opts_wscale(opts))
    {
//      while (opts_len % 2)
//        {
//          opts_len += TCP_OPTION_LEN_NOOP;
//          *data++ = TCP_OPTION_NOOP;
//        }
      *data++ = TCP_OPTION_WINDOW_SCALE;
      *data++ = TCP_OPTION_LEN_WINDOW_SCALE;
      *data++ = opts->wscale;
      opts_len += TCP_OPTION_LEN_WINDOW_SCALE;
    }

  if (tcp_opts_sack_permitted(opts))
    {
      *data++ = TCP_OPTION_SACK_PERMITTED;
      *data++ = TCP_OPTION_LEN_SACK_PERMITTED;
      opts_len += TCP_OPTION_LEN_SACK_PERMITTED;
    }

  if (tcp_opts_tstamp(opts))
    {
//      while (opts_len % 4 != 2)
//        {
//          opts_len += TCP_OPTION_LEN_NOOP;
//          *data++ = TCP_OPTION_NOOP;
//        }
      *data++ = TCP_OPTION_TIMESTAMP;
      *data++ = TCP_OPTION_LEN_TIMESTAMP;
      buf = clib_host_to_net_u32 (opts->tsval);
      clib_memcpy (data, &buf, sizeof (opts->tsval));
      data += sizeof (opts->tsval);
      buf = clib_host_to_net_u32 (opts->tsecr);
      clib_memcpy (data, &buf, sizeof (opts->tsecr));
      data += sizeof (opts->tsecr);
      opts_len += TCP_OPTION_LEN_TIMESTAMP;
    }

  if (tcp_opts_sack (opts))
    {
      int i;
      u32 n_sack_blocks = clib_min (vec_len(opts->sacks),
                                   TCP_OPTS_MAX_SACK_BLOCKS);

      if (n_sack_blocks != 0)
        {
          *data++ = TCP_OPTION_SACK_BLOCK;
          *data++ = 2 + n_sack_blocks * TCP_OPTION_LEN_SACK_BLOCK;
          for (i = 0; i < n_sack_blocks; i++)
            {
              buf = clib_host_to_net_u32 (opts->sacks[i].start);
              clib_memcpy (data, &buf, seq_len);
              data += seq_len;
              buf = clib_host_to_net_u32 (opts->sacks[i].end);
              clib_memcpy (data, &buf, seq_len);
              data += seq_len;
            }
          opts_len += 2 + n_sack_blocks * TCP_OPTION_LEN_SACK_BLOCK;
        }
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
  return opts_len;
}

always_inline int
tcp_make_syn_options (tcp_options_t *opts, u32 initial_wnd)
{
  u8 len = 0;

  opts->flags |= TCP_OPTS_FLAG_MSS;
  opts->mss = dummy_mtu; /*XXX discover that */
  len += TCP_OPTION_LEN_MSS;

  opts->flags |= TCP_OPTS_FLAG_WSCALE;
  opts->wscale = tcp_window_compute_scale (initial_wnd);
  len += TCP_OPTION_LEN_WINDOW_SCALE;

  opts->flags |= TCP_OPTS_FLAG_TSTAMP;
  opts->tsval = tcp_time_now ();
  opts->tsecr = 0;
  len += TCP_OPTION_LEN_TIMESTAMP;

  opts->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
  len += TCP_OPTION_LEN_SACK_PERMITTED;

  /* Align to needed boundary */
  len += TCP_OPTS_ALIGN - len % TCP_OPTS_ALIGN;
  return len;
}

always_inline int
tcp_make_synack_options (tcp_connection_t *tc, tcp_options_t *opts)
{
  u8 len = 0;

  opts->flags |= TCP_OPTS_FLAG_MSS;
  opts->mss = dummy_mtu; /*XXX discover that */
  len += TCP_OPTION_LEN_MSS;

  if (tcp_opts_wscale(&tc->opt))
    {
      opts->flags |= TCP_OPTS_FLAG_WSCALE;
      opts->wscale = tc->rcv_wscale;
      len += TCP_OPTION_LEN_WINDOW_SCALE;
    }

  if (tcp_opts_tstamp(&tc->opt))
    {
      opts->flags |= TCP_OPTS_FLAG_TSTAMP;
      opts->tsval = tcp_time_now ();
      opts->tsecr = tc->tsval_recent;
      len += TCP_OPTION_LEN_TIMESTAMP;
    }

  if (tcp_opts_sack_permitted (&tc->opt))
    {
      opts->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
      len += TCP_OPTION_LEN_SACK_PERMITTED;
    }

  /* Align to needed boundary */
  len += TCP_OPTS_ALIGN - len % TCP_OPTS_ALIGN;
  return len;
}

always_inline int
tcp_make_established_options (tcp_connection_t *tc, tcp_options_t *opts)
{
  u8 len = 0;

  opts->flags = 0;

  if (tcp_opts_tstamp (&tc->opt))
    {
      opts->flags |= TCP_OPTS_FLAG_TSTAMP;
      opts->tsval = tcp_time_now ();
      opts->tsecr = tc->tsval_recent;
      len += TCP_OPTION_LEN_TIMESTAMP;
    }
  if (tcp_opts_sack_permitted (&tc->opt))
    {
      if (vec_len(tc->sacks))
        {
          opts->flags |= TCP_OPTS_FLAG_SACK;
          opts->sacks = tc->sacks;
          opts->n_sack_blocks = vec_len(tc->sacks);
          len += 2 + 8 * opts->n_sack_blocks;
        }
    }

  /* Align to needed boundary */
  len += TCP_OPTS_ALIGN - len % TCP_OPTS_ALIGN;
  return len;
}

#define tcp_get_free_buffer_index(tm, bidx)                             \
do {                                                                    \
  u32 *my_tx_buffers, n_free_buffers;                                   \
  u32 cpu_index = tm->vlib_main->cpu_index;                             \
  my_tx_buffers = tm->tx_buffers[cpu_index];                            \
  if (PREDICT_FALSE(vec_len (my_tx_buffers) == 0))                      \
    {                                                                   \
      n_free_buffers = 32;      /* TODO config or macro */              \
      vec_validate (my_tx_buffers, n_free_buffers - 1);                 \
      _vec_len(my_tx_buffers) = vlib_buffer_alloc_from_free_list (      \
          tm->vlib_main, my_tx_buffers, n_free_buffers,                 \
          VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);                         \
      tm->tx_buffers[cpu_index] = my_tx_buffers;                        \
    }                                                                   \
  /* buffer shortage */                                                 \
  if (PREDICT_FALSE (vec_len (my_tx_buffers) == 0))                     \
    return;                                                             \
  *bidx = my_tx_buffers[_vec_len (my_tx_buffers)-1];                    \
  _vec_len (my_tx_buffers) -= 1;                                        \
} while (0)

always_inline void
tcp_reuse_buffer (vlib_main_t *vm, vlib_buffer_t *b)
{
  vlib_buffer_t *it = b;
  do
    {
      it->current_data = 0;
      it->current_length = 0;
      it->total_length_not_including_first_buffer = 0;
    }
  while ((it->flags & VLIB_BUFFER_NEXT_PRESENT)
      && (it = vlib_get_buffer (vm, it->next_buffer)));
}

/**
 * Convert buffer to ACK
 */
void
tcp_make_ack (tcp_connection_t *tc, vlib_buffer_t *b)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  u8 tcp_opts_len, tcp_hdr_opts_len;
  tcp_header_t *th;
  u16 wnd;

  tcp_reuse_buffer (vm, b);

  /* leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  wnd = tcp_window_to_advertise (tc);

  /* Make and write options */
  tcp_opts_len = tcp_make_established_options (tc, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = pkt_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->snd_nxt,
                     tc->rcv_nxt, tcp_hdr_opts_len, TCP_FLAG_ACK, wnd);

  tcp_options_write ((u8 *) (th + 1), snd_opts);

  /* Mark as ACK */
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
  vnet_buffer (b)->tcp.flags = TCP_BUF_FLAG_ACK;
}

/**
 * Convert buffer to SYN-ACK
 */
void
tcp_make_synack (tcp_connection_t *tc, vlib_buffer_t *b)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  u8 tcp_opts_len, tcp_hdr_opts_len;
  tcp_header_t *th;
  u16 initial_wnd;
  u32 time_now;

  memset(snd_opts, 0, sizeof (*snd_opts));

  tcp_reuse_buffer (vm, b);

  /* Leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  /* Set random initial sequence */
  time_now = tcp_time_now();

  tc->iss = random_u32 (&time_now);
  tc->snd_una = tc->iss;
  tc->snd_nxt = tc->iss + 1;

  initial_wnd = tcp_initial_window_to_advertise (tc);

  /* Make and write options */
  tcp_opts_len = tcp_make_synack_options (tc, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = pkt_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->iss,
                     tc->rcv_nxt, tcp_hdr_opts_len, TCP_FLAG_SYN | TCP_FLAG_ACK,
                     initial_wnd);

  tcp_options_write ((u8 *)(th + 1), snd_opts);

  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
  vnet_buffer (b)->tcp.flags = TCP_BUF_FLAG_ACK;
}

always_inline void
tcp_enqueue_to_ip_lookup (vlib_main_t *vm, vlib_buffer_t *b, u32 bi, u8 is_ip4)
{
  u32 *to_next, next_index;
  vlib_frame_t *f;

  b->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;
  b->error = 0;

  /* Default FIB for now */
  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;

  /* Send to IP lookup */
  next_index = is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
  f = vlib_get_frame_to_node (vm, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);
}

/**
 *  Send reset
 */
void
tcp_send_reset (vlib_buffer_t *pkt, u8 is_ip4)
{
  vlib_buffer_t *b;
  u32 bi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u8 tcp_hdr_len, flags = 0;
  tcp_header_t *th, *pkt_th;
  u32 seq, ack;

  tcp_get_free_buffer_index (tm, &bi);
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
      ack = clib_host_to_net_u32(vnet_buffer (pkt)->tcp.seq_end);
    }

  th = pkt_push_tcp_net_order (b, pkt_th->dst_port, pkt_th->src_port, seq, ack,
                               tcp_hdr_len, flags, 0);

  if (is_ip4)
    {
      ip4_header_t * ih, *pkt_ih;

      pkt_ih = vlib_buffer_get_current (b);

      ASSERT((pkt_ih->ip_version_and_header_length & 0xF0) == 0x40);

      ih = pkt_push_ipv4 (vm, b, &pkt_ih->dst_address, &pkt_ih->src_address,
                          IP_PROTOCOL_TCP);
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ih);
    }
  else
    {
      ip6_header_t * ih, *pkt_ih;
      int bogus = ~0;

      pkt_ih = vlib_buffer_get_current (b);

      ASSERT((pkt_ih->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60);
      ih = pkt_push_ipv6 (vm, b, &pkt_ih->dst_address, &pkt_ih->dst_address,
                          IP_PROTOCOL_TCP);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ih, &bogus);
      ASSERT(!bogus);
    }

  tcp_enqueue_to_ip_lookup (vm, b, bi, is_ip4);
}

/**
 *  Send SYN
 */
void
tcp_send_syn (tcp_connection_t *tc)
{
  vlib_buffer_t *b;
  u32 bi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u8 tcp_hdr_opts_len, tcp_opts_len;
  tcp_header_t *th;
  u32 time_now;
  u16 initial_wnd;
  tcp_options_t snd_opts;

  tcp_get_free_buffer_index (tm, &bi);
  b = vlib_get_buffer (vm, bi);

  /* Leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  /* Set random initial sequence */
  time_now = tcp_time_now();

  tc->iss = random_u32 (&time_now);
  tc->snd_una = tc->iss;
  tc->snd_nxt = tc->iss + 1;

  /* fifos are not allocated yet. Use some predefined value */
  initial_wnd = 16 << 10;

  /* Make and write options */
  memset (&snd_opts, 0, sizeof (snd_opts));
  tcp_opts_len = tcp_make_syn_options (&snd_opts, initial_wnd);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = pkt_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->iss,
                     tc->rcv_nxt, tcp_hdr_opts_len, TCP_FLAG_SYN,
                     initial_wnd);

  tcp_options_write ((u8 *)(th + 1), &snd_opts);

  if (tc->c_is_ip4)
    {
      ip4_header_t * ih;
      ih = pkt_push_ipv4 (vm, b, &tc->c_lcl_ip4, &tc->c_rmt_ip4,
                          IP_PROTOCOL_TCP);
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ih);
    }
  else
    {
      ip6_header_t * ih;
      int bogus = ~0;

      ih = pkt_push_ipv6 (vm, b, &tc->c_lcl_ip6, &tc->c_rmt_ip6,
                          IP_PROTOCOL_TCP);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ih, &bogus);
      ASSERT(!bogus);
    }

  tcp_enqueue_to_ip_lookup (vm, b, bi, tc->c_is_ip4);
}

always_inline void
tcp_enqueue_to_output (vlib_main_t *vm, vlib_buffer_t *b, u32 bi, u8 is_ip4)
{
  u32 *to_next, next_index;
  vlib_frame_t *f;

  b->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;
  b->error = 0;

  /* Decide where to send the packet */
  next_index = is_ip4 ? tcp4_output_node.index : tcp6_output_node.index;
  f = vlib_get_frame_to_node (vm, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);
}

/**
 *  Send FIN
 */
void
tcp_send_fin (tcp_connection_t *tc)
{
  vlib_buffer_t *b;
  u32 bi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  tcp_header_t *th;

  tcp_get_free_buffer_index (tm, &bi);
  b = vlib_get_buffer (vm, bi);

  /* Leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  tcp_make_ack (tc, b);

  th = vlib_buffer_get_current (b);

  th->flags |= TCP_FLAG_FIN;

  tcp_enqueue_to_output (vm, b, bi, tc->c_is_ip4);
}


/* Send delayed ACK when timer expires */
void
timer_delack_handler (u32 index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  tcp_connection_t *tc;
  vlib_buffer_t *b;
  u32 bi;

  tc = tcp_connection_get (index, vm->cpu_index);

  /* Get buffer */
  tcp_get_free_buffer_index (tm, &bi);
  b = vlib_get_buffer (vm, bi);

  /* Fill in the ACK */
  tcp_make_ack (tc, b);

  tc->timers[TCP_TIMER_DELACK] = TCP_TIMER_HANDLE_INVALID;
  tc->flags &= ~TCP_CONN_DELACK;

  tcp_enqueue_to_output (vm, b, bi, tc->c_is_ip4);
}

always_inline u32
tcp_session_has_ooo_data (tcp_connection_t *tc)
{
  stream_session_t *s = stream_session_get (tc->c_s_index, tc->c_thread_index);
  return svm_fifo_has_ooo_data (s->server_rx_fifo);
}

always_inline uword
tcp46_output_inline (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame,
                    int is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
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
          tcp_connection_t *tc0;
          tcp_header_t *th0;
          u32 error0 = TCP_ERROR_PKTS_SENT, next0 = TCP_OUTPUT_NEXT_DROP;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          tc0 = tcp_connection_get (vnet_buffer(b0)->tcp.connection_index,
                                 my_thread_index);
          th0 = vlib_buffer_get_current (b0);

          if (is_ip4)
            {
              ip4_header_t * ih0;
              ih0 = pkt_push_ipv4 (vm, b0, &tc0->c_lcl_ip4, &tc0->c_rmt_ip4,
                                   IP_PROTOCOL_TCP);
              th0->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ih0);
            }
          else
            {
              ip6_header_t * ih0;
              int bogus = ~0;

              ih0 = pkt_push_ipv6 (vm, b0, &tc0->c_lcl_ip6, &tc0->c_rmt_ip6,
                                   IP_PROTOCOL_TCP);
              th0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ih0,
                                                                 &bogus);
              ASSERT (!bogus);
            }

          /* Filter DUPACKs if there are no OOO segments left */
          if (PREDICT_FALSE(vnet_buffer (b0)->tcp.flags & TCP_BUF_FLAG_DUPACK))
            {
              tc0->snt_dupacks --;
              ASSERT (tc0->snt_dupacks >= 0);
              if (!tcp_session_has_ooo_data (tc0))
                {
                  error0 = TCP_ERROR_FILTERED_DUPACKS;
                  next0 = TCP_OUTPUT_NEXT_DROP;
                  goto done;
                }
            }

          /* If an ACK  */
//          if (vnet_buffer (b0)->tcp.flags & TCP_BUF_FLAG_ACK)
//            {
              tc0->rcv_las = tc0->rcv_nxt;

              /* Stop DELACK timer and fix flags */
              u32 handle = tc0->timers[TCP_TIMER_DELACK];
              tc0->flags &= ~(TCP_CONN_SNDACK | TCP_CONN_DELACK
                  | TCP_CONN_BURSTACK);
              if (handle != TCP_TIMER_HANDLE_INVALID)
                {
                  tcp_timer_stop (&tm->timer_wheels[my_thread_index], handle);
                  tc0->timers[TCP_TIMER_DELACK] = TCP_TIMER_HANDLE_INVALID;
                }
//            }

          /* set fib index to default and lookup node */
          /* XXX network virtualization (vrf/vni)*/
          vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
          vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

          b0->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;

          next0 =
              is_ip4 ? TCP_OUTPUT_NEXT_IP4_LOOKUP : TCP_OUTPUT_NEXT_IP6_LOOKUP;

         done:
          b0->error = error0 != 0 ? node->errors[error0] : 0;
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

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_output_node, tcp6_output)

/**
 * Read as much data as possible from the tx fifo, build a tcp packet and
 * ask that it be sent to tcp-output
 */
u32
tcp_push_header_uri (transport_connection_t *tconn, vlib_buffer_t *b)
{
  u32 advertise_wnd, data_len;
  tcp_connection_t *tc;
  u8 tcp_opts_len, tcp_hdr_opts_len, opts_write_len;
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  tcp_header_t *th;

  tc = (tcp_connection_t *)tconn;

  data_len = b->current_length;
  vnet_buffer (b)->tcp.flags = 0;

  /* Make and write options */
  memset (snd_opts, 0, sizeof (*snd_opts));
  tcp_opts_len = tcp_make_established_options (tc, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  advertise_wnd = tcp_window_to_advertise (tc);

  th = pkt_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->snd_nxt,
                     tc->rcv_nxt, tcp_hdr_opts_len, TCP_FLAG_ACK,
                     advertise_wnd);

  opts_write_len = tcp_options_write ((u8 *)(th + 1), snd_opts);

  ASSERT (opts_write_len == tcp_opts_len);

  /* Tag the buffer with the connection index  */
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;

  /* If we have un-ACKed data, tag the buffer as ACK XXX do flag fixing here */
  if (seq_gt (tc->rcv_nxt, tc->rcv_las))
    vnet_buffer (b)->tcp.flags = TCP_BUF_FLAG_ACK;

  tc->rcv_las = tc->rcv_nxt;
  tc->snd_nxt += data_len;

  if (tc->c_is_ip4)
    return URI_QUEUE_NEXT_TCP_IP4_OUTPUT;
  else
    return URI_QUEUE_NEXT_TCP_IP6_OUTPUT;
}