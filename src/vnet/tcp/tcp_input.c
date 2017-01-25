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
#include <vnet/tcp/tcp_packet.h>
#include <vnet/tcp/tcp.h>
#include <vnet/uri/uri_db.h>
#include <math.h>

static char *
tcp_error_strings[] =
{
#define tcp_error(n,s) s,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
};

/* All TCP nodes have the same outgoing arcs */
#define foreach_tcp_state_next                  \
  _ (DROP, "error-drop")                        \
  _ (TCP4_OUTPUT, "tcp4-output")                \
  _ (TCP6_OUTPUT, "tcp6-output")

typedef enum _tcp_established_next
{
#define _(s,n) TCP_ESTABLISHED_NEXT_##s,
  foreach_tcp_state_next
#undef _
  TCP_ESTABLISHED_N_NEXT,
} tcp_established_next_t;

typedef enum _tcp_rcv_process_next
{
#define _(s,n) TCP_RCV_PROCESS_NEXT_##s,
  foreach_tcp_state_next
#undef _
  TCP_RCV_PROCESS_N_NEXT,
} tcp_rcv_process_next_t;

typedef enum _tcp_syn_sent_next
{
#define _(s,n) TCP_SYN_SENT_NEXT_##s,
  foreach_tcp_state_next
#undef _
  TCP_SYN_SENT_N_NEXT,
} tcp_syn_sent_next_t;

typedef enum _tcp_listen_next
{
#define _(s,n) TCP_LISTEN_NEXT_##s,
  foreach_tcp_state_next
#undef _
  TCP_LISTEN_N_NEXT,
} tcp_listen_next_t;

/* Generic, state independent indices */
typedef enum _tcp_state_next
{
#define _(s,n) TCP_NEXT_##s,
  foreach_tcp_state_next
#undef _
  TCP_STATE_N_NEXT,
} tcp_state_next_t;

#define tcp_next_output(is_ip4) (is_ip4 ? TCP_NEXT_TCP4_OUTPUT          \
                                        : TCP_NEXT_TCP6_OUTPUT)

vlib_node_registration_t tcp4_established_node;
vlib_node_registration_t tcp6_established_node;

/**
 * Validate segment sequence number. As per RFC793:
 *
 * Segment Receive Test
 *      Length  Window
 *      ------- -------  -------------------------------------------
 *      0       0       SEG.SEQ = RCV.NXT
 *      0       >0      RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *      >0      0       not acceptable
 *      >0      >0      RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *                      or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
 *
 * This ultimately consists in checking if segment falls within the window.
 * The one important difference compared to RFC793 is that we use rcv_las,
 * or the rcv_nxt at last ack sent instead of rcv_nxt since that's the
 * peer's reference when computing our receive window.
 *
 * This accepts only segments within the window.
 */
always_inline u8
tcp_segment_in_window (tcp_connection_t *tc, u32 seq, u32 end_seq)
{
  return seq_leq (end_seq, tc->rcv_las + tc->rcv_wnd)
      && seq_geq (seq, tc->rcv_nxt);
}

void
tcp_options_parse (tcp_header_t *th, tcp_options_t *to)
{
  const u8 *data;
  u8 opt_len, opts_len, kind;
  int j;
  sack_block_t b;

  opts_len = (tcp_doff(th) << 2) - sizeof (tcp_header_t);
  data = (const u8 *)(th + 1);

  /* Zero out all but SACK_PERMITTED which is set with SYN and we use as
   * flag for connection */
  to->flags &= TCP_OPTS_FLAG_SACK_PERMITTED;

  for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
      kind = data[0];

      /* Get options length */
      if (kind == TCP_OPTION_EOL)
        break;
      else if (kind == TCP_OPTION_NOOP)
        opt_len = 1;
      else
        {
          /* broken options */
          if (opts_len < 2)
            break;
          opt_len = data[1];

          /* weird option length */
          if (opt_len < 2 || opt_len > opts_len)
            break;
        }

      /* Parse options */
      switch (kind)
      {
        case TCP_OPTION_MSS:
          if ((opt_len == TCP_OPTION_LEN_MSS) && tcp_syn (th))
            {
              to->flags |= TCP_OPTS_FLAG_MSS;
              to->mss = clib_net_to_host_u16 (*(u16 *) (data + 2));
            }
          break;
        case TCP_OPTION_WINDOW_SCALE:
          if ((opt_len == TCP_OPTION_LEN_WINDOW_SCALE) && tcp_syn (th))
            {
              to->flags |= TCP_OPTS_FLAG_WSCALE;
              to->wscale = data[2];
              if (to->wscale > TCP_MAX_WND_SCALE)
                {
                  clib_warning ("Illegal window scaling value: %d", to->wscale);
                  to->wscale = TCP_MAX_WND_SCALE;
                }
            }
          break;
        case TCP_OPTION_TIMESTAMP:
          if (opt_len == TCP_OPTION_LEN_TIMESTAMP)
            {
              to->flags |= TCP_OPTS_FLAG_TSTAMP;
              to->tsval = clib_net_to_host_u32 (*(u32 *)(data + 2));
              to->tsecr = clib_net_to_host_u32 (*(u32 *)(data + 6));
            }
          break;
        case TCP_OPTION_SACK_PERMITTED:
          if (opt_len == TCP_OPTION_LEN_SACK_PERMITTED && tcp_syn (th))
            to->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
          break;
        case TCP_OPTION_SACK_BLOCK:
          /* If SACK permitted was not advertised or a SYN, break */
          if ((to->flags & TCP_OPTS_FLAG_SACK_PERMITTED) == 0 || tcp_syn (th))
           break;

          /* If too short or not correctly formatted, break */
          if (opt_len < 10 || ((opt_len - 2) % TCP_OPTION_LEN_SACK_BLOCK))
            break;

          to->flags |= TCP_OPTS_FLAG_SACK;
          to->n_sack_blocks = (opt_len - 2) / TCP_OPTION_LEN_SACK_BLOCK;
          vec_reset_length (to->sacks);
          for (j = 0; j < to->n_sack_blocks; j++)
            {
              b.start = clib_net_to_host_u32 (*(u32 *)(data + 2 + 4*j));
              b.end = clib_net_to_host_u32 (*(u32 *)(data + 6 + 4*j));
              vec_add1 (to->sacks, b);
            }
          break;
        default:
          /* Nothing to see here */
          continue;
      }
    }
}

always_inline int
tcp_segment_check_paws (tcp_connection_t *tc)
{
  /* XXX normally test for timestamp should be lt instead of leq, but for
   * local testing this is not enough */
  return tcp_opts_tstamp(&tc->opt) && tc->tsval_recent
      && timestamp_lt (tc->opt.tsval, tc->tsval_recent);
}

/**
 * Validate incoming segment as per RFC793 p. 69 and RFC1323 p. 19
 *
 * It first verifies if segment has a wrapped sequence number (PAWS) and then
 * does the processing associated to the first four steps (ignoring security
 * and precedence): sequence number, rst bit and syn bit checks.
 *
 * @return 0 if segments passes validation.
 */
always_inline int
tcp_segment_validate (vlib_main_t *vm, tcp_connection_t *tc0, vlib_buffer_t *b0,
                      tcp_header_t *th0, u32 *next0)
{
  u8 paws_failed;

  if (PREDICT_FALSE(!tcp_ack(th0) && !tcp_rst(th0) && !tcp_syn(th0)))
    return -1;

  tcp_options_parse (th0, &tc0->opt);

  /* RFC1323: Check against wrapped sequence numbers (PAWS). If we have
   * timestamp to echo and it's less than tsval_recent, drop segment
   * but still send an ACK in order to retain TCP's mechanism for detecting
   * and recovering from half-open connections */
  paws_failed = tcp_segment_check_paws (tc0);
  if (paws_failed)
    {
      clib_warning ("paws failed");

      /* If it just so happens that a segment updates tsval_recent for a
       * segment over 24 days old, invalidate tsval_recent. */
      if (timestamp_lt(tc0->tsval_recent_age + TCP_PAWS_IDLE,
                       tcp_time_now()))
        {
          /* Age isn't reset until we get a valid tsval (bsd inspired) */
          tc0->tsval_recent = 0;
        }
      else
        {
          /* Drop after ack if not rst */
          if (!tcp_rst (th0))
            {
              tcp_make_ack (tc0, b0);
              *next0 = tcp_next_output (tc0->c_is_ip4);
              return -1;
            }
        }
    }

  /* 1st: check sequence number */
  if (!tcp_segment_in_window (tc0, vnet_buffer (b0)->tcp.seq_number,
                              vnet_buffer (b0)->tcp.seq_end))
    {
      if (!tcp_rst (th0))
        {
          /* Send dup ack */
          tcp_make_ack(tc0, b0);
          *next0 = tcp_next_output (tc0->c_is_ip4);
        }
      return -1;
    }

  /* 2nd: check the RST bit */
  if (tcp_rst (th0))
    {
      /* TODO reset connection */
      return -1;
    }

  /* 3rd: check security and precedence (skip) */

  /* 4th: check the SYN bit */
  if (tcp_syn (th0))
    {
      tcp_send_reset (b0, tc0->c_is_ip4);
      return -1;
    }

  /* If PAWS passed and segment in window, save timestamp */
  if (!paws_failed)
    {
      tc0->tsval_recent = tc0->opt.tsval;
      tc0->tsval_recent_age = tcp_time_now ();
    }

  return 0;
}

always_inline int
tcp_incoming_ack_is_acceptable (tcp_connection_t *tc0, vlib_buffer_t *tb0)
{
  /* SND.UNA =< SEG.ACK =< SND.NXT */
  return (seq_leq (tc0->snd_una, vnet_buffer (tb0)->tcp.ack_number)
      && seq_leq (vnet_buffer (tb0)->tcp.ack_number, tc0->snd_nxt));
}

always_inline int
tcp_incoming_ack_established (tcp_connection_t *tc0, vlib_buffer_t *tb0,
                              tcp_header_t *tcp0, u32 *next0, u32 *error0)
{
  /* If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be ignored.*/
  if (seq_lt(vnet_buffer (tb0)->tcp.ack_number, tc0->snd_una))
    {
      *error0 = TCP_ERROR_ACK_DUP;
      return -1;
    }

  /* If the ACK acks something not yet sent (SEG.ACK > SND.NXT) then send an
   * ACK, drop the segment, and return  */
  if (seq_gt(vnet_buffer (tb0)->tcp.ack_number, tc0->snd_nxt))
    {
      tcp_make_ack (tc0, tb0);
      *next0 = tcp_next_output (tc0->c_is_ip4);
      *error0 = TCP_ERROR_ACK_INVALID;
      return -1;
    }

  /* Update acked local seq number and remove acked segments from
   * retransmission queue TODO*/
  tc0->snd_una = vnet_buffer (tb0)->tcp.ack_number;

  /* Update window TODO wnd scaling*/
  tc0->snd_wnd = clib_net_to_host_u32 (tcp0->window) << tc0->opt.wscale;
  tc0->snd_wl1 = vnet_buffer (tb0)->tcp.seq_number;

  return 0;
}

/**
 * Build SACK list as per RFC2018.
 *
 * Makes sure the first block contains the segment that generated the current
 * ACK and the following ones are the ones most recently reported in SACK
 * blocks.
 *
 * @param tc TCP connection for which the SACK list is updated
 * @param start Start sequence number of the newest SACK block
 * @param end End sequence of the newest SACK block
 */
static void
tcp_sack_list_update (tcp_connection_t *tc, u32 start, u32 end)
{
  sack_block_t *new_list = 0, block;
  u32 n_elts;
  int i;
  u8 new_head = 0;

  /* If the first segment is ooo add it to the list. Last write might've moved
   * rcv_nxt over the first segment. */
  if (seq_lt (tc->rcv_nxt, start))
    {
      block.start = start;
      block.end = end;
      vec_add1 (new_list, block);
      new_head = 1;
    }

  /* Find the blocks still worth keeping. */
  for (i = 0; i < vec_len (tc->sacks); i++)
    {
      /* Discard if:
       * 1) rcv_nxt advanced beyond current block OR
       * 2) Segment overlapped by the first segment, i.e., it has been merged
       *    into it.*/
      if (seq_leq(tc->sacks[i].start, tc->rcv_nxt)
          || seq_leq (tc->sacks[i].start, end))
        continue;

      /* Save subsequent segments to new SACK list. */
      n_elts = clib_min (vec_len (tc->sacks) - i,
                        TCP_MAX_SACK_BLOCKS - new_head);
      vec_insert_elts (new_list, &tc->sacks[i], n_elts, new_head);
      break;
    }

  /* Replace old vector with new one */
  vec_free (tc->sacks);
  tc->sacks = new_list;
}

/** Enqueue data for delivery to application */
always_inline u32
tcp_session_enqueue_data (tcp_connection_t *tc, vlib_buffer_t *b, u16 data_len)
{
  stream_session_t *s0;
  int written;

  /* Pure ACK. Update rcv_nxt and be done. */
  if (PREDICT_FALSE (data_len == 0))
    {
      tc->rcv_nxt = vnet_buffer (b)->tcp.seq_end;
      return TCP_ERROR_PURE_ACK;
    }

  s0 = stream_session_get (tc->c_s_index, tc->c_thread_index);

  written = stream_session_enqueue_data (s0, vlib_buffer_get_current (b),
                                         data_len, 1 /* queue event */);

  /* Update rcv_nxt */
  if (PREDICT_TRUE(written == data_len))
    {
      tc->rcv_nxt = vnet_buffer (b)->tcp.seq_end;
    }
  /* If more data written than expected, account for out-of-order bytes.*/
  else if (written > data_len)
    {
      tc->rcv_nxt = vnet_buffer (b)->tcp.seq_end + written - data_len;

      /* Send ACK confirming the update */
      tc->flags |= TCP_CONN_SNDACK;

      /* Update SACK list if need be */
      if (tcp_opts_sack_permitted (&tc->opt))
        {
          /* Remove SACK blocks that have been delivered */
          tcp_sack_list_update (tc, tc->rcv_nxt, tc->rcv_nxt);
        }
    }
  else
    {
      ASSERT(0);
      return TCP_ERROR_FIFO_FULL;
    }

  return TCP_ERROR_ENQUEUED;
}

/** Enqueue out-of-order data */
always_inline u32
tcp_session_enqueue_ooo (tcp_connection_t *tc, vlib_buffer_t *b, u16 data_len)
{
  stream_session_t *s0;
  u32 offset, seq;

  s0 = stream_session_get (tc->c_s_index, tc->c_thread_index);
  seq = vnet_buffer (b)->tcp.seq_number;
  offset = seq - tc->rcv_nxt;

  if (svm_fifo_enqueue_with_offset2 (s0->server_rx_fifo, s0->pid, offset,
                                     data_len, vlib_buffer_get_current (b)))
    return TCP_ERROR_FIFO_FULL;

  /* Update SACK list if in use */
  if (tc->opt.flags & TCP_OPTS_FLAG_SACK_PERMITTED)
    {
      ooo_segment_t *newest;
      u32 start, end;

      /* Get the newest segment from the fifo */
      newest = svm_fifo_newest_ooo_segment (s0->server_rx_fifo);
      start = tc->rcv_nxt + ooo_segment_offset (s0->server_rx_fifo, newest);
      end = tc->rcv_nxt + ooo_segment_end_offset (s0->server_rx_fifo, newest);

      tcp_sack_list_update (tc, start, end);
    }

  return TCP_ERROR_ENQUEUED;
}

always_inline u8
tcp_timer_is_active (tcp_connection_t *tc, tcp_timers_e timer)
{
  return tc->timers[timer] != TCP_TIMER_HANDLE_INVALID;
}

/**
 * Check if ACK could be delayed. DELACK timer is set only after frame is
 * processed so this can return true for a full bursts of packets.
 */
always_inline int
tcp_can_delack (tcp_connection_t *tc)
{
  /* If there's no DELACK timer set and the last window sent wasn't 0 we
   * can safely delay. */
  if (!tcp_timer_is_active (tc, TCP_TIMER_DELACK)
      && (tc->flags & TCP_CONN_SENT_RCV_WND0) == 0
      && (tc->flags & TCP_CONN_SNDACK) == 0)
    return 1;

  return 0;
}

static int
tcp_segment_rcv (tcp_main_t *tm, tcp_connection_t *tc, vlib_buffer_t *b,
                 u16 n_data_bytes, u32 *next0)
{
  u32 error = 0;

  /* Handle out-of-order data */
  if (PREDICT_FALSE (vnet_buffer (b)->tcp.seq_number != tc->rcv_nxt))
    {
      error = tcp_session_enqueue_ooo (tc, b, n_data_bytes);

      /* Don't send more than 3 dupacks per burst
       * XXX decide if this is good */
      if (tc->snt_dupacks < 3)
        {
          /* RFC2581: Send DUPACK for fast retransmit */
          tcp_make_ack (tc, b);
          *next0 = tcp_next_output (tc->c_is_ip4);

          /* Mark as DUPACK. We may filter these in output if
           * the burst fills the holes. */
          vnet_buffer (b)->tcp.flags = TCP_BUF_FLAG_DUPACK;

          tc->snt_dupacks++;
        }

      goto done;
    }

  /* In order data, enqueue. Fifo figures out by itself if any out-of-order
   * segments can be enqueued after fifo tail offset changes. */
  error = tcp_session_enqueue_data (tc, b, n_data_bytes);

  /* Check if ACK can be delayed */
  if (tcp_can_delack (tc))
    {
      /* Nothing to do for pure ACKs */
      if (n_data_bytes == 0)
        goto done;

      /* If connection has not been previously marked for delay ack
       * add it to the list and flag it */
      if (!tc->flags & TCP_CONN_DELACK)
        {
          vec_add1 (tm->delack_connections[tc->c_thread_index],
                    tc->c_c_index);
          tc->flags |= TCP_CONN_DELACK;
        }
    }
  /* If it can't be delayed */
  else
    {
      /* Check if a packet has already been enqueued to output for burst.
       * If yes, then drop this one, otherwise, let it pass through to
       * output */
      if ((tc->flags & TCP_CONN_BURSTACK) == 0)
        {
          *next0 = tcp_next_output (tc->c_is_ip4);
          tcp_make_ack (tc, b);
          error = TCP_ERROR_ENQUEUED;

          /* TODO: maybe add counter to ensure N acks will be sent/burst */
          tc->flags |= TCP_CONN_BURSTACK;
        }
    }

 done:
  return error;
}

void
delack_timers_init (tcp_main_t *tm, u32 thread_index)
{
  tcp_connection_t *tc;
  u32 i, *conns;
  tcp_timer_wheel_t *tw;

  tw = &tm->timer_wheels[thread_index];
  conns = tm->delack_connections[thread_index];
  for (i = 0; i < vec_len(conns); i++)
    {
      tc = pool_elt_at_index (tm->connections[thread_index], conns[i]);
      ASSERT(0 != tc);

      tc->timers[TCP_TIMER_DELACK] = tcp_timer_start (tw, conns[i],
                                                      TCP_TIMER_DELACK,
                                                      TCP_DELACK_TIME);
    }
  vec_reset_length (tm->delack_connections[thread_index]);
}

always_inline uword
tcp46_established_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                          vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  u32 my_thread_index = vm->cpu_index, errors = 0;
  tcp_main_t *tm = vnet_get_tcp_main ();

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
          tcp_header_t *th0 = 0;
          tcp_connection_t *tc0;
          ip4_header_t * ip40;
          ip6_header_t * ip60;
          u32 n_advance_bytes0, n_data_bytes0;
          u32 next0 = TCP_ESTABLISHED_NEXT_DROP, error0 = TCP_ERROR_ENQUEUED;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          tc0 = tcp_connection_get (vnet_buffer(b0)->tcp.connection_index,
                                 my_thread_index);

          /* Checksum computed by ipx_local no need to compute again */

          if (is_ip4)
            {
              ip40 = vlib_buffer_get_current (b0);
              th0 = ip4_next_header (ip40);
              n_advance_bytes0 = (ip4_header_bytes (ip40)
                  + tcp_header_bytes (th0));
              n_data_bytes0 = clib_net_to_host_u16 (ip40->length)
                  - n_advance_bytes0;
            }
          else
            {
              ip60 = vlib_buffer_get_current (b0);
              th0 = ip6_next_header (ip60);
              n_advance_bytes0 = tcp_header_bytes (th0);
              n_data_bytes0 = clib_net_to_host_u16 (ip60->payload_length)
                  - n_advance_bytes0;
              n_advance_bytes0 += sizeof(ip60[0]);
            }

          /* SYNs, FINs and data consume sequence numbers */
          vnet_buffer (b0)->tcp.seq_end = vnet_buffer (b0)->tcp.seq_number
              + tcp_is_syn (th0) + tcp_is_fin (th0) + n_data_bytes0;

          /* TODO header prediction fast path */

          /* 1-4: check SEQ, RST, SYN */
          if (PREDICT_FALSE(tcp_segment_validate (vm, tc0, b0, th0, &next0)))
            {
              error0 = TCP_ERROR_SEGMENT_INVALID;
              goto drop;
            }

          /* 5: check the ACK field  */
          if (tcp_incoming_ack_established (tc0, b0, th0, &next0, &error0))
            {
              goto drop;
            }

          /* 6: check the URG bit TODO */

          /* 7: process the segment text */
          vlib_buffer_advance (b0, n_advance_bytes0);
          error0 = tcp_segment_rcv (tm, tc0, b0, n_data_bytes0, &next0);

       drop:
          b0->error = node->errors[error0];
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  errors = session_manager_flush_enqueue_events (my_thread_index);
  if (errors)
    {
      if (is_ip4)
        vlib_node_increment_counter (vm, tcp4_established_node.index,
                                     TCP_ERROR_EVENT_FIFO_FULL, errors);
      else
        vlib_node_increment_counter (vm, tcp6_established_node.index,
                                     TCP_ERROR_EVENT_FIFO_FULL, errors);
    }

  delack_timers_init (tm, my_thread_index);

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

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_ESTABLISHED_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_established_node, tcp4_established)

VLIB_REGISTER_NODE (tcp6_established_node) = {
  .function = tcp6_established,
  .name = "tcp6-established",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_ESTABLISHED_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_established_node, tcp6_established)

vlib_node_registration_t tcp4_syn_sent_node;
vlib_node_registration_t tcp6_syn_sent_node;

static void
tcp_timers_init (tcp_connection_t *tc)
{
  int i;
  for (i = 0; i < TCP_N_TIMERS; i++)
    {
      tc->timers[i] = TCP_TIMER_HANDLE_INVALID;
    }
}

always_inline uword
tcp46_syn_sent_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                          vlib_frame_t * from_frame, int is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u32 n_left_from, next_index, * from, * to_next;
  u32 my_thread_index = vm->cpu_index, errors = 0;
  u8 sst = is_ip4 ? SESSION_TYPE_IP4_TCP : SESSION_TYPE_IP6_TCP;

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
          u32 bi0, ack0, seq0;
          vlib_buffer_t * b0;
          tcp_header_t *tcp0 = 0;
          tcp_connection_t *tc0;
          ip4_header_t * ip40;
          ip6_header_t * ip60;
          u32 n_advance_bytes0, n_data_bytes0;
          tcp_connection_t *new_tc0;
          u32 next0 = TCP_SYN_SENT_NEXT_DROP, error0 = TCP_ERROR_ENQUEUED;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          tc0 = tcp_half_open_connection_get (
              vnet_buffer(b0)->tcp.connection_index);

          ack0 = vnet_buffer (b0)->tcp.ack_number;
          seq0 = vnet_buffer (b0)->tcp.seq_number;

          /* Checksum computed by ipx_local no need to compute again */

          if (is_ip4)
            {
              ip40 = vlib_buffer_get_current (b0);
              tcp0 = ip4_next_header (ip40);
              n_advance_bytes0 = (ip4_header_bytes (ip40)
                  + tcp_header_bytes (tcp0));
              n_data_bytes0 = clib_net_to_host_u16 (ip40->length)
                  - n_advance_bytes0;
            }
          else
            {
              ip60 = vlib_buffer_get_current (b0);
              tcp0 = ip6_next_header (ip60);
              n_advance_bytes0 = tcp_header_bytes (tcp0);
              n_data_bytes0 = clib_net_to_host_u16 (ip60->payload_length)
                  - n_advance_bytes0;
              n_advance_bytes0 += sizeof(ip60[0]);
            }

          if (PREDICT_FALSE(
              !tcp_ack (tcp0) && !tcp_rst (tcp0) && !tcp_syn (tcp0)))
            goto drop;

          /* SYNs, FINs and data consume sequence numbers */
          vnet_buffer (b0)->tcp.seq_end = seq0 + tcp_is_syn(tcp0)
              + tcp_is_fin(tcp0) + n_data_bytes0;

          /*
           *  1. check the ACK bit
           */

          /*
           *   If the ACK bit is set
           *     If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
           *     the RST bit is set, if so drop the segment and return)
           *       <SEQ=SEG.ACK><CTL=RST>
           *     and discard the segment.  Return.
           *     If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
           */
          if (tcp_ack (tcp0))
            {
              if (ack0 <= tc0->iss || ack0 > tc0->snd_nxt)
                {
                  if (!tcp_rst (tcp0))
                    tcp_send_reset (b0, is_ip4);

                  goto drop;
                }

              /* Make sure ACK is valid */
              if (tc0->snd_una > ack0)
                goto drop;
            }

          /*
           * 2. check the RST bit
           */

          if (tcp_rst (tcp0))
            {
              /* If ACK is acceptable, signal client */
              if (tcp_ack(tcp0))
                stream_session_reset_notify (&tc0->connection);

              /* and close connection */
              tcp_connection_close (tm, tc0);
              goto drop;
            }

          /*
           * 3. check the security and precedence (skipped)
           */

          /*
           * 4. check the SYN bit
           */

          /* No SYN flag. Drop. */
          if (!tcp_syn (tcp0))
            goto drop;

          /* Valid SYN or SYN-ACK. Move connection from half-open pool to
           * current thread pool. */
          pool_get(tm->connections[my_thread_index], new_tc0);
          clib_memcpy (new_tc0, tc0, sizeof(*new_tc0));

          new_tc0->c_thread_index = my_thread_index;

          /* Stop connection establishment timer and cleanup syn_sent connection */
          tcp_timer_stop (&tm->timer_wheels[my_thread_index],
                          new_tc0->timers[TCP_TIMER_KEEP]);

          /* XXX lock */
          pool_put (tm->half_open_connections, tc0);

          /* rcv_nxt is incremented when data segment is read */
          new_tc0->rcv_nxt = vnet_buffer (b0)->tcp.seq_end;
          new_tc0->irs = seq0;

          /* Parse options */
          tcp_options_parse (tcp0, &new_tc0->opt);
          if (tcp_opts_tstamp(&new_tc0->opt))
            {
              new_tc0->tsval_recent = new_tc0->opt.tsval;
              new_tc0->tsval_recent_age = tcp_time_now ();
            }

          if (tcp_opts_wscale (&new_tc0->opt))
            new_tc0->snd_wscale = new_tc0->opt.wscale;

          new_tc0->snd_wnd = clib_net_to_host_u32 (tcp0->window)
              << new_tc0->opt.wscale;

          new_tc0->snd_wl1 = seq0;

          tcp_timers_init (new_tc0);

          /* SYN-ACK: See if we can switch to ESTABLISHED state */
          if (tcp_ack (tcp0))
            {
              new_tc0->snd_una = ack0;

              /* Our SYN is ACKed: we have iss < ack = snd_una */

              /* TODO XXX dequeue acknowledged segments */

              new_tc0->state = TCP_CONNECTION_STATE_ESTABLISHED;

              /* Notify app that we have connection */
              stream_session_connect_notify (&new_tc0->connection, sst, 0);

              /* Make sure after data segment processing ACK is sent */
              new_tc0->flags |= TCP_CONN_SNDACK;
            }
          /* SYN: Simultaneous open. Change state to SYN-RCVD and send SYN-ACK */
          else
            {
              new_tc0->state = TCP_CONNECTION_STATE_SYN_RCVD;

              /* Notify app that we have connection XXX */
              stream_session_connect_notify (&new_tc0->connection, sst, 0);

              tcp_make_synack (new_tc0, b0);
              next0 = tcp_next_output (is_ip4);

              goto drop;
            }

          /* Read data, if any */
          if (n_data_bytes0)
            {
              error0 = tcp_segment_rcv (tm, new_tc0, b0, n_data_bytes0, &next0);
              if (error0 == TCP_ERROR_PURE_ACK)
                error0 = TCP_ERROR_SYN_ACKS_RCVD;
            }
          else
            {
              tcp_make_ack (new_tc0, b0);
              next0 = tcp_next_output (new_tc0->c_is_ip4);
            }

         drop:

          b0->error = error0 ? node->errors[error0] : 0;
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  errors = session_manager_flush_enqueue_events (my_thread_index);
  if (errors)
    {
      if (is_ip4)
        vlib_node_increment_counter (vm, tcp4_established_node.index,
                                     TCP_ERROR_EVENT_FIFO_FULL, errors);
      else
        vlib_node_increment_counter (vm, tcp6_established_node.index,
                                     TCP_ERROR_EVENT_FIFO_FULL, errors);
    }

  return from_frame->n_vectors;
}

static uword
tcp4_syn_sent (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
  return tcp46_syn_sent_inline (vm, node, from_frame, 1 /* is_ip4 */);
}

static uword
tcp6_syn_sent_rcv (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
  return tcp46_syn_sent_inline (vm, node, from_frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (tcp4_syn_sent_node) = {
  .function = tcp4_syn_sent,
  .name = "tcp4-syn-sent",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_SYN_SENT_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_SYN_SENT_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_syn_sent_node, tcp4_syn_sent)


VLIB_REGISTER_NODE (tcp6_syn_sent_node) = {
  .function = tcp6_syn_sent_rcv,
  .name = "tcp6-syn-sent",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_SYN_SENT_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_SYN_SENT_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_syn_sent_node, tcp6_syn_sent_rcv)

static void
tcp_session_close (tcp_connection_t *tc)
{
  /* TODO */
  clib_warning ("unimplemented");
}

/**
 * Handles reception for all states except LISTEN, SYN-SEND and ESTABLISHED
 * as per RFC793 p. 64
 */
always_inline uword
tcp46_rcv_process_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * from_frame, int is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u32 n_left_from, next_index, * from, * to_next;
  u32 my_thread_index = vm->cpu_index, errors = 0;

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
          tcp_header_t *tcp0 = 0;
          tcp_connection_t *tc0;
          ip4_header_t * ip40;
          ip6_header_t * ip60;
          u32 n_advance_bytes0, n_data_bytes0;
          u32 next0 = TCP_RCV_PROCESS_NEXT_DROP, error0 = TCP_ERROR_ENQUEUED;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          tc0 = tcp_connection_get (vnet_buffer(b0)->tcp.connection_index,
                                    my_thread_index);

          /* Checksum computed by ipx_local no need to compute again */

          if (is_ip4)
            {
              ip40 = vlib_buffer_get_current (b0);
              tcp0 = ip4_next_header (ip40);
              n_advance_bytes0 = (ip4_header_bytes (ip40)
                  + tcp_header_bytes (tcp0));
              n_data_bytes0 = clib_net_to_host_u16 (ip40->length)
                  - n_advance_bytes0;
            }
          else
            {
              ip60 = vlib_buffer_get_current (b0);
              tcp0 = ip6_next_header (ip60);
              n_advance_bytes0 = tcp_header_bytes (tcp0);
              n_data_bytes0 = clib_net_to_host_u16 (ip60->payload_length)
                  - n_advance_bytes0;
              n_advance_bytes0 += sizeof(ip60[0]);
            }

          /* SYNs, FINs and data consume sequence numbers */
          vnet_buffer (b0)->tcp.seq_end = vnet_buffer (b0)->tcp.seq_number
              + tcp_is_syn (tcp0) + tcp_is_fin (tcp0) + n_data_bytes0;

          /*
           * Special treatment for CLOSED
           */
          switch (tc0->state)
            {
            case TCP_CONNECTION_STATE_CLOSED:
              goto drop;
              break;
            }

          /*
           * For all other states (except LISTEN)
           */

          /* 1-4: check SEQ, RST, SYN */
          if (PREDICT_FALSE(tcp_segment_validate (vm, tc0, b0, tcp0, &next0)))
            {
              error0 = TCP_ERROR_SEGMENT_INVALID;
              goto drop;
            }

          /* 5: check the ACK field  */
          switch (tc0->state)
          {
            case TCP_CONNECTION_STATE_SYN_RCVD:
              /*
               * If the segment acknowledgment is not acceptable, form a
               * reset segment,
               *  <SEQ=SEG.ACK><CTL=RST>
               * and send it.
               */
              if (!tcp_incoming_ack_is_acceptable (tc0, b0))
                {
                  tcp_send_reset (b0, is_ip4);
                  goto drop;
                }
              /* Switch state to ESTABLISHED */
              tc0->state = TCP_CONNECTION_STATE_ESTABLISHED;

              /* Initialize session variables */
              tc0->snd_una = vnet_buffer (b0)->tcp.ack_number;
              tc0->snd_wnd = clib_net_to_host_u32 (tcp0->window)
                  << tc0->opt.wscale;
              tc0->snd_wl1 = vnet_buffer (b0)->tcp.seq_number;
              tc0->snd_wl2 = vnet_buffer (b0)->tcp.ack_number;

              /* Shoulder tap the server */
              stream_session_accept_notify (&tc0->connection);
              break;
            case TCP_CONNECTION_STATE_ESTABLISHED:
              /* XXX Packets may have been enqueued before state change */
              if (tcp_incoming_ack_established (tc0, b0, tcp0, &next0,
                                                &error0))
                goto drop;

              break;
            case TCP_CONNECTION_STATE_FIN_WAIT_1:
              /* XXX In addition to the processing for the ESTABLISHED state, if
               * our FIN is now acknowledged then enter FIN-WAIT-2 and
               * continue processing in that state. */
              if (!tcp_incoming_ack_established (tc0, b0, tcp0, &next0,
                                                 &error0))
                tc0->state = TCP_CONNECTION_STATE_FIN_WAIT_2;
              else
                goto drop;
              break;
            case TCP_CONNECTION_STATE_FIN_WAIT_2:
              /* In addition to the processing for the ESTABLISHED state, if
               * the retransmission queue is empty, the user's CLOSE can be
               * acknowledged ("ok") but do not delete the TCB. */
              if (tcp_incoming_ack_established (tc0, b0, tcp0, &next0,
                                                &error0))
                {
                  /* check if rtx queue is empty and ack CLOSE TODO*/
                }
              else
                {
                  goto drop;
                }
              break;
            case TCP_CONNECTION_STATE_CLOSE_WAIT:
              /* Do the same processing as for the ESTABLISHED state. */
              if (tcp_incoming_ack_established (tc0, b0, tcp0, &next0,
                                                &error0))
                goto drop;
              break;
            case TCP_CONNECTION_STATE_CLOSING:
              /* In addition to the processing for the ESTABLISHED state, if
               * the ACK acknowledges our FIN then enter the TIME-WAIT state,
               * otherwise ignore the segment. */
              if (tcp_incoming_ack_established (tc0, b0, tcp0, &next0,
                                                &error0))
                goto drop;

              /* XXX test that send queue empty */
              tc0->state = TCP_CONNECTION_STATE_TIME_WAIT;
              goto drop;

              break;
            case TCP_CONNECTION_STATE_LAST_ACK:
              /* The only thing that can arrive in this state is an
               * acknowledgment of our FIN. If our FIN is now acknowledged,
               * delete the TCB, enter the CLOSED state, and return. */

              if (!tcp_incoming_ack_is_acceptable (tc0, b0))
                goto drop;

              tcp_session_close (tc0);
              goto drop;

              break;
            case TCP_CONNECTION_STATE_TIME_WAIT:
              /* The only thing that can arrive in this state is a
               * retransmission of the remote FIN. Acknowledge it, and restart
               * the 2 MSL timeout. */

              /* TODO */

              break;
            default:
              ASSERT(0);
          }
          
          /* 6: check the URG bit TODO*/

          /* 7: process the segment text */
          switch (tc0->state)
          {
            case TCP_CONNECTION_STATE_ESTABLISHED:
            case TCP_CONNECTION_STATE_FIN_WAIT_1:
            case TCP_CONNECTION_STATE_FIN_WAIT_2:
              error0 = tcp_segment_rcv (tm, tc0, b0, n_data_bytes0, &next0);
              break;
            case TCP_CONNECTION_STATE_CLOSE_WAIT:
            case TCP_CONNECTION_STATE_CLOSING:
            case TCP_CONNECTION_STATE_LAST_ACK:
            case TCP_CONNECTION_STATE_TIME_WAIT:
              /* This should not occur, since a FIN has been received from the
               * remote side.  Ignore the segment text. */
              break;
          }

          b0->error = error0 ? node->errors[error0] : 0;

         drop:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  errors = session_manager_flush_enqueue_events (my_thread_index);
  if (errors)
    {
      if (is_ip4)
        vlib_node_increment_counter (vm, tcp4_established_node.index,
                                     TCP_ERROR_EVENT_FIFO_FULL, errors);
      else
        vlib_node_increment_counter (vm, tcp6_established_node.index,
                                     TCP_ERROR_EVENT_FIFO_FULL, errors);
    }

  return from_frame->n_vectors;
}

static uword
tcp4_rcv_process (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
  return tcp46_rcv_process_inline (vm, node, from_frame, 1 /* is_ip4 */);
}

static uword
tcp6_rcv_process (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
  return tcp46_rcv_process_inline (vm, node, from_frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (tcp4_rcv_process_node) = {
  .function = tcp4_rcv_process,
  .name = "tcp4-rcv-process",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_RCV_PROCESS_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_RCV_PROCESS_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_rcv_process_node, tcp4_rcv_process)


VLIB_REGISTER_NODE (tcp6_rcv_process_node) = {
  .function = tcp6_rcv_process,
  .name = "tcp6-rcv-process",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_RCV_PROCESS_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_RCV_PROCESS_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_rcv_process_node, tcp6_rcv_process)

vlib_node_registration_t tcp4_listen_node;
vlib_node_registration_t tcp6_listen_node;

/**
 * LISTEN state processing as per RFC 793 p. 65
 */
always_inline uword
tcp46_listen_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                     vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  u32 my_thread_index = vm->cpu_index;
  tcp_main_t *tm = vnet_get_tcp_main ();
  u8 sst = is_ip4 ? SESSION_TYPE_IP4_TCP : SESSION_TYPE_IP6_TCP;

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
          tcp_header_t *th0 = 0;
          tcp_connection_t *lc0;
          ip4_header_t * ip40;
          ip6_header_t * ip60;
          tcp_connection_t *child0;
          u32 error0 = TCP_ERROR_SYNS_RCVD, next0 = TCP_LISTEN_NEXT_DROP;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          lc0 = tcp_listener_get (vnet_buffer(b0)->tcp.connection_index);

          if (is_ip4)
            {
              ip40 = vlib_buffer_get_current (b0);
              th0 = ip4_next_header (ip40);
            }
          else
            {
              ip60 = vlib_buffer_get_current (b0);
              th0 = ip6_next_header (ip60);
            }

          /* Create child session. No syn-flood protection for now */

          /* 1. first check for an RST */
          if (tcp_rst (th0))
            goto drop;

          /* 2. second check for an ACK */
          if (tcp_ack (th0))
            {
              tcp_send_reset (b0, is_ip4);
              goto drop;
            }

          /* 3. check for a SYN (did that already) */

          /* Create child session and send SYN-ACK */
          pool_get(tm->connections[my_thread_index], child0);
          memset (child0, 0, sizeof(*child0));

          child0->c_c_index = child0 - tm->connections[my_thread_index];
          child0->c_lcl_port = lc0->c_lcl_port;
          child0->c_rmt_port = th0->src_port;
          child0->c_is_ip4 = is_ip4;
          child0->c_thread_index = my_thread_index;
          tcp_timers_init (child0);

          if (is_ip4)
            {
              child0->c_lcl_ip4.as_u32 = ip40->dst_address.as_u32;
              child0->c_rmt_ip4.as_u32 = ip40->src_address.as_u32;
            }
          else
            {
              clib_memcpy (&child0->c_lcl_ip6, &ip60->dst_address,
                           sizeof(ip6_address_t));
              clib_memcpy (&child0->c_rmt_ip6, &ip60->src_address,
                           sizeof(ip6_address_t));
            }

          if (stream_session_accept (&child0->connection, lc0->c_s_index, sst,
                                     0/* notify */))
            {
              error0 = TCP_ERROR_CREATE_SESSION_FAIL;
              goto drop;
            }

          tcp_options_parse (th0, &child0->opt);

          child0->irs = vnet_buffer (b0)->tcp.seq_number;
          child0->rcv_nxt = vnet_buffer (b0)->tcp.seq_number + 1;
          child0->state = TCP_CONNECTION_STATE_SYN_RCVD;

          /* RFC1323: TSval timestamps sent on {SYN} and {SYN,ACK}
           * segments are used to initialize PAWS. */
          if (tcp_opts_tstamp(&child0->opt))
            {
              child0->tsval_recent = child0->opt.tsval;
              child0->tsval_recent_age = tcp_time_now ();
            }

          /* Reuse buffer to make syn-ack and send */
          tcp_make_synack (child0, b0);
          next0 = tcp_next_output (is_ip4);

         drop:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }

          b0->error = error0 ? node->errors[error0] : 0;

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

static uword
tcp4_listen (vlib_main_t * vm, vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
  return tcp46_listen_inline (vm, node, from_frame, 1 /* is_ip4 */);
}

static uword
tcp6_listen (vlib_main_t * vm, vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
  return tcp46_listen_inline (vm, node, from_frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (tcp4_listen_node) = {
  .function = tcp4_listen,
  .name = "tcp4-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_LISTEN_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_listen_node, tcp4_listen)

VLIB_REGISTER_NODE (tcp6_listen_node) = {
  .function = tcp6_listen,
  .name = "tcp6-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_LISTEN_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_listen_node, tcp6_listen)

vlib_node_registration_t tcp4_input_node;
vlib_node_registration_t tcp6_input_node;

typedef enum _tcp_input_next
{
  TCP_INPUT_NEXT_DROP,
  TCP_INPUT_NEXT_LISTEN,
  TCP_INPUT_NEXT_RCV_PROCESS,
  TCP_INPUT_NEXT_SYN_SENT,
  TCP_INPUT_NEXT_ESTABLISHED,
  TCP_INPUT_N_NEXT
} tcp_input_next_t;

#define foreach_tcp4_input_next                 \
  _ (DROP, "error-drop")                        \
  _ (LISTEN, "tcp4-listen")                     \
  _ (RCV_PROCESS, "tcp4-rcv-process")           \
  _ (SYN_SENT, "tcp4-syn-sent")                 \
  _ (ESTABLISHED, "tcp4-established")

#define foreach_tcp6_input_next                 \
  _ (DROP, "error-drop")                        \
  _ (LISTEN, "tcp6-listen")                     \
  _ (RCV_PROCESS, "tcp6-rcv-process")           \
  _ (SYN_SENT, "tcp6-syn-sent")                 \
  _ (ESTABLISHED, "tcp6-established")

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
format_tcp_state (u8 *s, va_list *args)
{
  tcp_fsm_states_t *state = va_arg (*args, tcp_fsm_states_t *);

  if (state[0] < TCP_N_CONNECTION_STATE)
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
  u32 n_left_from, next_index, * from, * to_next;
  u32 my_thread_index = vm->cpu_index;
  tcp_main_t *tm = vnet_get_tcp_main ();
  session_manager_main_t *ssm = vnet_get_session_manager_main ();

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
          tcp_header_t * tcp0 = 0;
          tcp_connection_t *tc0;
          ip4_header_t * ip40;
          ip6_header_t * ip60;
          u32 error0 = TCP_ERROR_NO_LISTENER, next0 = TCP_INPUT_NEXT_DROP;
          u8 flags0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          if (is_ip4)
            {
              ip40 = vlib_buffer_get_current (b0);
              tcp0 = ip4_next_header (ip40);

              /* lookup session */
              tc0 = (tcp_connection_t *) stream_session_lookup_transport4 (
                  ssm, &ip40->dst_address, &ip40->src_address, tcp0->dst_port,
                  tcp0->src_port, SESSION_TYPE_IP4_TCP, my_thread_index);
            }
          else
            {
              ip60 = vlib_buffer_get_current (b0);
              tcp0 = ip6_next_header (ip60);
              tc0 = (tcp_connection_t *) stream_session_lookup_transport6 (
                  ssm, &ip60->src_address, &ip60->dst_address, tcp0->src_port,
                  tcp0->dst_port, SESSION_TYPE_IP6_TCP, my_thread_index);
            }

          /* Session exists */
          if (PREDICT_TRUE(0 != tc0))
            {
              /* Save connection index */
              vnet_buffer (b0)->tcp.connection_index = tc0->c_c_index;
              vnet_buffer (b0)->tcp.seq_number = clib_net_to_host_u32 (
                  tcp0->seq_number);
              vnet_buffer (b0)->tcp.ack_number = clib_net_to_host_u32 (
                  tcp0->ack_number);

              flags0 = tcp0->flags
                  & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN);
              next0 = tm->dispatch_table[tc0->state][flags0].next;
              error0 = tm->dispatch_table[tc0->state][flags0].error;
            }

          b0->error = error0 ? node->errors[error0] : 0;

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
    foreach_tcp4_input_next
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
    foreach_tcp6_input_next
#undef _
  },

  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_input_node, tcp6_input)

void
tcp_update_time (f64 now, u32 thread_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_timer_expire_timers (&tm->timer_wheels[thread_index], now);
}

static void
tcp_dispatch_table_init (tcp_main_t *tm)
{
  int i, j;
  for (i = 0; i < ARRAY_LEN(tm->dispatch_table); i++)
    for (j = 0; j < ARRAY_LEN(tm->dispatch_table[i]); j++)
      {
        tm->dispatch_table[i][j].next = TCP_INPUT_NEXT_DROP;
        tm->dispatch_table[i][j].error = TCP_ERROR_LOOKUP_DROPS;
      }

#define _(t,f,n,e)                                                      \
do {                                                                    \
    tm->dispatch_table[TCP_CONNECTION_STATE_##t][f].next = (n);         \
    tm->dispatch_table[TCP_CONNECTION_STATE_##t][f].error = (e);        \
} while (0)

  /* SYNs for new connections -> tcp-listen. */
  _(LISTEN, TCP_FLAG_SYN, TCP_INPUT_NEXT_LISTEN, TCP_ERROR_NONE);
  /* ACK for for a SYN-ACK -> tcp-rcv-process. */
  _(SYN_RCVD, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  /* SYN-ACK for a SYN */
  _(SYN_SENT, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_SYN_SENT,
    TCP_ERROR_NONE);
  /* ACK for for established connection -> tcp-established. */
  _(ESTABLISHED, TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  /* FIN for for established connection -> tcp-established. */
  _(ESTABLISHED, TCP_FLAG_FIN, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
#undef _
}

clib_error_t *
tcp_input_init (vlib_main_t * vm)
{
  clib_error_t * error = 0;
  tcp_main_t *tm = vnet_get_tcp_main ();

  if ((error = vlib_call_init_function(vm, tcp_init)))
    return error;

  /* Initialize dispatch table. */
  tcp_dispatch_table_init (tm);

  return error;
}

VLIB_INIT_FUNCTION (tcp_input_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */