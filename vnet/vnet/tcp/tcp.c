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
 * This ultimately reduces to checking if segment falls within the window.
 * The one important difference compared to RFC793 is that we use rcv_las,
 * or the rcv_nxt at last ack sent instead of rcv_nxt since that's the
 * peer's reference when computing our receive window.
 */
always_inline u8
tcp_sequence_is_valid (tcp_session_t *ts, u32 seq, u32 end_seq)
{
  return !seq_gt (seq, ts->rcv_nxt + tcp_actual_receive_window(ts))
      && !seq_lt (end_seq, ts->rcv_las);
}

void
tcp_options_parse (tcp_header_t *th, tcp_options_t *to)
{
  const u8 *data;
  u8 opt_len, opts_len, kind;

  opts_len = (th->data_offset << 2) - sizeof (tcp_header_t);
  data = (const u8 *)(th + 1);
  to->flags = 0;

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
          if (opt_len == TCP_OPTION_LEN_MSS && th->syn)
            {
              to->mss_flag = 1;
              to->mss = clib_net_to_host_u16 (*(u16 *) (data + 2));
            }
          break;
        case TCP_OPTION_WINDOW_SCALE:
          if (opt_len == TCP_OPTION_LEN_WINDOW_SCALE && th->syn)
            {
              to->wscale_flag = 1;
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
              to->tstamp_flag = 1;
              to->tsval = clib_net_to_host_u32 (*(u32 *)(data + 2));
              to->tsecr = clib_net_to_host_u32 (*(u32 *)(data + 6));
            }
          break;
        case TCP_OPTION_SACK_PERMITTED:
          if (opt_len == TCP_OPTION_LEN_SACK_PERMITTED && th->syn)
            to->sack_flag = 1;
          break;
        case TCP_OPTION_SACK_BLOCK:
          clib_warning ("Not implemented!");
          break;
        default:
          /* Nothing to see here */
          continue;
      }
    }
}

always_inline int
tcp_segment_test_paws (tcp_session_t *ts)
{
  return ts->opt.tstamp_flag && ts->opt.tsval_recent
      && timestamp_lt (ts->opt.tsval, ts->opt.tsval_recent);
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
tcp_segment_validate (vlib_main_t *vm, tcp_session_t *ts0, vlib_buffer_t *tb0,
                      tcp_header_t *th0, u8 is_ip4)
{
  u8 paws_passed;

  if (PREDICT_FALSE(!th0->ack && !th0->rst && !th0->syn))
    return -1;

  tcp_options_parse (th0, &ts0->opt);

  /* RFC1323: Check against wrapped sequence numbers (PAWS). If we have
   * timestamp to echo and it's less than tsval_recent, drop segment
   * but still send an ACK in order to retain TCP's mechanism for detecting
   * and recovering from half-open connections */
  if ((paws_passed = tcp_segment_test_paws (ts0)))
    {
      /* If it just so happens that a segment updates tsval_recent for a
       * segment over 24 days old, invalidate tsval_recent. */
      if (timestamp_lt(ts0->opt.tsval_recent_age + TCP_PAWS_IDLE,
                       tcp_time_now()))
        {
          /* Age isn't reset until we get a valid tsval (bsd inspired) */
          ts0->opt.tsval_recent = 0;
        }
      else
        {
          /* Drop after ack if not rst */
          if (!th0->rst)
            {
              tcp_send_dupack (ts0, is_ip4);
              return -1;
            }
        }
    }

  /* 1st: check sequence number */
  if (!tcp_sequence_is_valid (ts0, vnet_buffer (tb0)->tcp.seq_number,
                              vnet_buffer (tb0)->tcp.end_seq))
    {
      if (!th0->rst)
        {
          tcp_send_dupack (ts0, is_ip4);
        }
      return -1;
    }

  /* 2nd: check the RST bit */
  if (th0->rst)
    {
      /* TODO reset connection */
      return -1;
    }

  /* 3rd: check security and precedence (skip) */

  /* 4th: check the SYN bit */
  if (th0->syn)
    {
      /* TODO send RST */
      return -1;
    }

  /* If PAWS passed and segment in window, save timestamp */
  if (paws_passed)
    {
      ts0->opt.tsval_recent = ts0->opt.tsval;
      ts0->opt.tsval_recent_age = tcp_time_now ();
    }

  return 0;
}

always_inline int
tcp_incoming_ack_is_acceptable (tcp_session_t *ts0, vlib_buffer_t *tb0)
{
  /* SND.UNA =< SEG.ACK =< SND.NXT */
  return (seq_leq (ts0->snd_una, vnet_buffer (tb0)->tcp.ack_number)
      && seq_leq (vnet_buffer (tb0)->tcp.ack_number, ts0->snd_nxt));
}

always_inline int
tcp_incoming_ack_established (tcp_session_t *ts0, vlib_buffer_t *tb0,
                              tcp_header_t *tcp0, u8 is_ip4)
{
  /* If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be ignored.*/
  if (seq_lt(vnet_buffer (tb0)->tcp.ack_number, ts0->snd_una))
    {
      return 1;
    }

  /* If the ACK acks something not yet sent (SEG.ACK > SND.NXT) then send an
   * ACK, drop the segment, and return  */
  if (seq_lt(vnet_buffer (tb0)->tcp.ack_number, ts0->snd_nxt))
    {
      tcp_send_ack (ts0, is_ip4);
      return -1;
    }

  /* Update acked local seq number and remove acked segments from
   * retransmission queue TODO*/
  ts0->snd_una = vnet_buffer (tb0)->tcp.ack_number;

  /* Update window TODO wnd scaling*/
  ts0->snd_wnd = clib_net_to_host_u32 (tcp0->window) << ts0->opt.wscale;
  ts0->snd_wl1 = vnet_buffer (tb0)->tcp.seq_number;

  return 0;
}

/* Check if we have space in rx fifo to push more bytes */
always_inline u8
tcp_session_no_space (tcp_session_t *ts, u32 my_thread_index, u16 data_len0)
{
  stream_session_t *s = stream_session_get (ts->s_s_index, my_thread_index);

  if (PREDICT_FALSE(s->session_state != SESSION_STATE_READY))
    return TCP_ERROR_NOT_READY;

  if (PREDICT_FALSE(data_len0 > svm_fifo_max_enqueue (s->server_rx_fifo)))
    return TCP_ERROR_FIFO_FULL;

  return 0;
}

/** Enqueue data for delivery to application */
always_inline int
tcp_session_enqueue_data (stream_session_t *s0, u8 *data0, u16 data_len0)
{
  stream_server_main_t *ssm = &stream_server_main;
  svm_fifo_t *f0;
  u8 my_enqueue_epoch;

  /* Make sure there's enough space left. We might've filled the pipes */
  if (PREDICT_FALSE(data_len0 > svm_fifo_max_enqueue (s0->server_rx_fifo)))
    return TCP_ERROR_FIFO_FULL;

  my_enqueue_epoch = ++ssm->current_enqueue_epoch[s0->session_thread_index];

  f0 = s0->server_rx_fifo;

  svm_fifo_enqueue_nowait2 (f0, s0->pid, data_len0, (u8 *) data0);

  /* We need to send an RX event on this fifo */
  if (s0->enqueue_epoch != my_enqueue_epoch)
    {
      s0->enqueue_epoch = my_enqueue_epoch;
      vec_add1(
          ssm->session_indices_to_enqueue_by_thread[s0->session_thread_index],
          s0 - ssm->sessions[s0->session_thread_index]);
    }

  return 0;
}

void
send_enqueue_events (vlib_main_t *vm, u32 my_thread_index, u8 is_ip4)
{
  u32 *session_indices_to_enqueue;
  stream_server_main_t *ssm = &stream_server_main;
  int i;
  static u32 serial_number;

  session_indices_to_enqueue =
    ssm->session_indices_to_enqueue_by_thread[my_thread_index];

  for (i = 0; i < vec_len (session_indices_to_enqueue); i++)
    {
      fifo_event_t evt;
      unix_shared_memory_queue_t * q;
      stream_session_t * s0;
      stream_server_t *ss0;

      /* Get session */
      s0 = stream_session_get (session_indices_to_enqueue[i], my_thread_index);

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
          if (is_ip4)
            vlib_node_increment_counter (vm, tcp4_established_node.index,
                                         TCP_ERROR_FIFO_FULL, 1);
          else
            vlib_node_increment_counter (vm, tcp6_established_node.index,
                                         TCP_ERROR_FIFO_FULL, 1);
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
}

always_inline int
tcp_segment_rcv (tcp_session_t *ts, u32 my_thread_index, vlib_buffer_t *b,
                 u16 n_data_bytes, u8 is_ip4)
{
  stream_session_t *s = stream_session_get (ts->s_s_index, my_thread_index);

  u32 error = 0;

  if (vnet_buffer (b)->tcp.seq_number == ts->rcv_nxt)
    {
      error = tcp_session_enqueue_data (s, vlib_buffer_get_current (b),
                                        n_data_bytes);
    }
  else
    {
      /* TODO take care of OOO */
    }

  if (!error)
    {
      /* Update receive next */
      ts->rcv_nxt = vnet_buffer (b)->tcp.end_seq;
    }

  /* Send ack*/
  tcp_send_ack (ts, is_ip4);

  return error;
}

always_inline uword
tcp46_established_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                          vlib_frame_t * from_frame, int is_ip4)
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
          tcp_header_t *tcp0 = 0;
          tcp_session_t *ts0;
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
          ts0 = tcp_session_get (vnet_buffer(b0)->tcp.session_index,
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
          vnet_buffer (b0)->tcp.end_seq = vnet_buffer (b0)->tcp.seq_number
              + tcp0->syn + tcp0->fin + n_advance_bytes0;

          error0 = tcp_session_no_space (ts0, my_thread_index, n_data_bytes0);
          if (PREDICT_FALSE(error0))
            goto drop;

          /* TODO header prediction fast path */

          /* 1-4: check SEQ, RST, SYN */
          if (PREDICT_FALSE(tcp_segment_validate (vm, ts0, b0, tcp0, is_ip4)))
            {
              error0 = TCP_ERROR_SEGMENT_INVALID;
              goto drop;
            }

          /* 5: check the ACK field  */
          if (tcp_incoming_ack_established (ts0, b0, tcp0, is_ip4) < 0)
            goto drop;

          /* 6: check the URG bit TODO */

          /* 7: process the segment text */
          vlib_buffer_advance (b0, n_advance_bytes0);
          error0 = tcp_segment_rcv (ts0, my_thread_index, b0, n_data_bytes0,
                                    is_ip4);

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

  send_enqueue_events (vm, my_thread_index, is_ip4);

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
  .name = "tcp6-established",
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

static uword tcp46_establish_inline (vlib_main_t * vm, 
                                     vlib_node_runtime_t * node,
                                     vlib_frame_t * from_frame,
                                     int is_ip4)
{
  clib_warning ("STUB called");
  return 0;
}

static uword
tcp4_establish (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
  return tcp46_establish_inline (vm, node, from_frame, 1 /* is_ip4 */);
}

VLIB_REGISTER_NODE (tcp4_establish_node) = {
  .function = tcp4_establish,
  .name = "tcp4-establish",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .runtime_data_bytes = sizeof (tcp_input_runtime_t),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
};

static uword
tcp6_establish (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
  return tcp46_establish_inline (vm, node, from_frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (tcp6_establish_node) = {
  .function = tcp6_establish,
  .name = "tcp6-establish",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .runtime_data_bytes = sizeof (tcp_input_runtime_t),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
};

#define foreach_tcp_rcv_process_next            \
  _ (DROP, "error-drop")

typedef enum _tcp_rcv_process_next
{
#define _(s,n) TCP_RCV_PROCESS_NEXT_##s,
  foreach_tcp_rcv_process_next
#undef _
  TCP_RCV_PROCESS_N_NEXT,
} tcp_rcv_process_next_t;

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_established_node, tcp6_established)

static int
tcp_state_synsent_rcv ()
{
  /* TODO */

  /*
   *  first check the ACK bit
   */

  /*
   *   If the ACK bit is set
   *     If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
   *     the RST bit is set, if so drop the segment and return)
   *       <SEQ=SEG.ACK><CTL=RST>
   *     and discard the segment.  Return.
   *     If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
   */


  /*
   * second check the RST bit
   */

  /*
   * third check the security and precedence (skipped)
   */

  /*
   * fourth check the SYN bit
   */

  /*
   * fifth, if neither of the SYN or RST bits is set then drop the
   *   segment and return.
   */

  return 0;
}

static void
tcp_session_close (tcp_session_t *ts)
{
  /* TODO */
  clib_warning ("unimplemented");
}

static void
tcp_notify_accept_server (tcp_session_t *ts, u32 my_thread_index)
{
  stream_server_main_t *ssm = &stream_server_main;
  stream_server_t *ss;
  stream_session_t *s;

  s = stream_session_get (ts->s_s_index, my_thread_index);

  /* Get session's server */
  ss = pool_elt_at_index(ssm->servers, s->server_index);

  /* Shoulder-tap the server */
  ss->session_create_callback (ss, s, ssm->vpp_event_queues[my_thread_index]);
}

/**
 * Handles all states except LISTEN and ESTABLISHED as per RFC793 p. 64
 */
always_inline uword
tcp46_rcv_process_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * from_frame, int is_ip4)
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
          tcp_header_t *tcp0 = 0;
          tcp_session_t *ts0;
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
          ts0 = tcp_session_get (vnet_buffer(b0)->tcp.session_index,
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

          /*
           * Special treatment for CLOSED and SYN-SENT
           */
          switch (ts0->state)
          {
            case TCP_CONNECTION_STATE_CLOSED:
              goto drop;
              break;
            case TCP_CONNECTION_STATE_SYN_SENT:
              tcp_state_synsent_rcv ();
              break;
          }

          /*
           * For all other states (except LISTEN and ESTABLISHED)
           */

          /* 1-4: check SEQ, RST, SYN */
          if (PREDICT_FALSE(tcp_segment_validate (vm, ts0, b0, tcp0, is_ip4)))
            {
              error0 = TCP_ERROR_SEGMENT_INVALID;
              goto drop;
            }

          /* 5: check the ACK field  */
          switch (ts0->state)
          {
            case TCP_CONNECTION_STATE_SYN_RCVD:
              /*
               * If the segment acknowledgment is not acceptable, form a
               * reset segment,
               *  <SEQ=SEG.ACK><CTL=RST>
               * and send it.
               */
              if (!tcp_incoming_ack_is_acceptable (ts0, b0))
                {
                  tcp_send_reset (b0, is_ip4);
                  goto drop;
                }
              /* Switch state to ESTABLISHED */
              ts0->state = TCP_CONNECTION_STATE_ESTABLISHED;

              /* Initialize session variables */
              ts0->snd_una = vnet_buffer (b0)->tcp.ack_number;
              ts0->snd_wnd = clib_net_to_host_u32 (tcp0->window)
                  << ts0->opt.wscale;
              ts0->snd_wl1 = vnet_buffer (b0)->tcp.seq_number;
              ts0->snd_wl2 = vnet_buffer (b0)->tcp.ack_number;

              /* Shoulder tap the server */
              tcp_notify_accept_server (ts0, my_thread_index);
              break;
            case TCP_CONNECTION_STATE_FIN_WAIT_1:
              /* In addition to the processing for the ESTABLISHED state, if
               * our FIN is now acknowledged then enter FIN-WAIT-2 and
               * continue processing in that state. */
              if (tcp_incoming_ack_established (ts0, b0, tcp0, is_ip4) >= 0)
                ts0->state = TCP_CONNECTION_STATE_FIN_WAIT_2;
              else
                goto drop;
              break;
            case TCP_CONNECTION_STATE_FIN_WAIT_2:
              /* In addition to the processing for the ESTABLISHED state, if
               * the retransmission queue is empty, the user's CLOSE can be
               * acknowledged ("ok") but do not delete the TCB. */
              if (tcp_incoming_ack_established (ts0, b0, tcp0, is_ip4) >= 0)
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
              if (tcp_incoming_ack_established (ts0, b0, tcp0, is_ip4) < 0)
                goto drop;
              break;
            case TCP_CONNECTION_STATE_CLOSING:
              /* In addition to the processing for the ESTABLISHED state, if
               * the ACK acknowledges our FIN then enter the TIME-WAIT state,
               * otherwise ignore the segment. */
              if (tcp_incoming_ack_established (ts0, b0, tcp0, is_ip4) < 0)
                goto drop;

              /* XXX test that send queue empty */
              ts0->state = TCP_CONNECTION_STATE_TIME_WAIT;
              goto drop;

              break;
            case TCP_CONNECTION_STATE_LAST_ACK:
              /* The only thing that can arrive in this state is an
               * acknowledgment of our FIN. If our FIN is now acknowledged,
               * delete the TCB, enter the CLOSED state, and return. */

              if (!tcp_incoming_ack_is_acceptable (ts0, b0))
                goto drop;

              tcp_session_close (ts0);
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
          switch (ts0->state)
          {
            case TCP_CONNECTION_STATE_ESTABLISHED:
            case TCP_CONNECTION_STATE_FIN_WAIT_1:
            case TCP_CONNECTION_STATE_FIN_WAIT_2:
              tcp_segment_rcv (ts0, my_thread_index, b0, n_data_bytes0, is_ip4);
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

  .n_next_nodes = TCP_RCV_PROCESS_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_RCV_PROCESS_NEXT_##s] = n,
    foreach_tcp_rcv_process_next
#undef _
  },
};

VLIB_REGISTER_NODE (tcp6_rcv_process_node) = {
  .function = tcp6_rcv_process,
  .name = "tcp6-rcv-process",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_RCV_PROCESS_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_RCV_PROCESS_NEXT_##s] = n,
    foreach_tcp_rcv_process_next
#undef _
  },
};

#define foreach_tcp_listen_next            \
  _ (DROP, "error-drop")

typedef enum _tcp_listen_next
{
#define _(s,n) TCP_LISTEN_NEXT_##s,
  foreach_tcp_listen_next
#undef _
  TCP_LISTEN_N_NEXT,
} tcp_listen_next_t;

vlib_node_registration_t tcp4_listen_node;
vlib_node_registration_t tcp6_listen_node;

always_inline uword
tcp46_listen_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                          vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  u32 my_thread_index = vm->cpu_index;
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
          tcp_header_t *tcp0 = 0;
          tcp_session_t *ts0;
          ip4_header_t * ip40;
          ip6_header_t * ip60;
          tcp_session_t *child0;
          u32 error0 = TCP_ERROR_NO_LISTENER, next0 = TCP_LISTEN_NEXT_DROP;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          ts0 = tcp_session_get (vnet_buffer(b0)->tcp.session_index,
                                 my_thread_index);

          if (is_ip4)
            {
              ip40 = vlib_buffer_get_current (b0);
              tcp0 = ip4_next_header (ip40);
            }
          else
            {
              ip60 = vlib_buffer_get_current (b0);
              tcp0 = ip6_next_header (ip60);
            }

          /* Create child session. No syn-flood protection for now */

          pool_get(tm->sessions[my_thread_index], child0);
          child0->s_t_index = child0 - tm->sessions[my_thread_index];
          child0->s_lcl_port = ts0->s_lcl_port;
          child0->s_rmt_port = clib_net_to_host_u16(tcp0->src_port);
          if (is_ip4)
            {
              child0->s_lcl_ip4.as_u32 = ip40->dst_address.as_u32;
              child0->s_rmt_ip4.as_u32 = ip40->src_address.as_u32;
            }
          else
            {
              clib_memcpy (&child0->s_lcl_ip6, &ip60->dst_address,
                           sizeof(ip6_address_t));
              clib_memcpy (&child0->s_rmt_ip6, &ip60->src_address,
                           sizeof(ip6_address_t));
            }

          error0 = stream_session_create (
              ts0->s_s_index, child0->s_t_index, my_thread_index,
              is_ip4 ? SESSION_TYPE_IP4_TCP : SESSION_TYPE_IP6_TCP,
              /* notify */0);

          if (!error0)
            {

              tcp_options_parse (tcp0, &child0->opt);

              child0->irs = vnet_buffer (b0)->tcp.seq_number;
              child0->rcv_nxt = vnet_buffer (b0)->tcp.seq_number + 1;
              child0->state = TCP_CONNECTION_STATE_SYN_RCVD;

              /* send syn-ack */
              tcp_send_synack (child0, is_ip4);
            }

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

  .runtime_data_bytes = sizeof (tcp_input_runtime_t),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_LISTEN_NEXT_##s] = n,
    foreach_tcp_listen_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_listen_node, tcp4_listen)

VLIB_REGISTER_NODE (tcp6_listen_node) = {
  .function = tcp6_listen,
  .name = "tcp6-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .runtime_data_bytes = sizeof (tcp_input_runtime_t),

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,

  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_LISTEN_NEXT_##s] = n,
    foreach_tcp_listen_next
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
  TCP_INPUT_NEXT_ESTABLISH,
  TCP_INPUT_NEXT_ESTABLISHED,
  TCP_INPUT_N_NEXT
} tcp_input_next_t;

#define foreach_tcp4_input_next                 \
  _ (DROP, "error-drop")                        \
  _ (LISTEN, "tcp4-listen")                     \
  _ (ESTABLISH, "tcp4-establish")               \
  _ (ESTABLISHED, "tcp4-established")

#define foreach_tcp6_input_next                 \
  _ (DROP, "error-drop")                        \
  _ (LISTEN, "tcp6-listen")                     \
  _ (ESTABLISH, "tcp6-establish")               \
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
format_tcp_state (u8 * s, va_list * args)
{
  tcp_fsm_states_t *state = va_arg (args, tcp_fsm_states_t *);

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
          stream_session_t * s0;
          tcp_session_t *ts0;
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
              s0 = stream_session_lookup4 (&ip40->dst_address,
                                           &ip40->src_address, tcp0->dst_port,
                                           tcp0->src_port, SESSION_TYPE_IP4_TCP,
                                           my_thread_index);
            }
          else
            {
              ip60 = vlib_buffer_get_current (b0);
              tcp0 = ip6_next_header (ip60);
              s0 = stream_session_lookup6 (&ip60->src_address,
                                           &ip60->dst_address, tcp0->src_port,
                                           tcp0->dst_port, SESSION_TYPE_IP6_TCP,
                                           my_thread_index);
            }

          /* Session exists */
          if (PREDICT_TRUE(0 != s0))
            {
              ts0 = tcp_session_get (s0->transport_session_index,
                                     my_thread_index);

              /* Save session index */
              vnet_buffer (b0)->tcp.session_index = s0->transport_session_index;
              vnet_buffer (b0)->tcp.seq_number = clib_net_to_host_u32 (
                  tcp0->seq_number);
              vnet_buffer (b0)->tcp.ack_number = clib_net_to_host_u32 (
                  tcp0->ack_number);

              flags0 = tcp0->flags
                  & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN);
              next0 = tm->dispatch_table[ts0->state][flags0].next;
              error0 = tm->dispatch_table[ts0->state][flags0].error;
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
    foreach_tcp6_input_next
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

u16 *
tcp_established_get_port_next_index (vlib_main_t * vm, u16 port, u8 is_ip6)
{
  tcp_input_runtime_t * rt;
  rt = vlib_node_get_runtime_data (
      vm, is_ip6 ? tcp6_established_node.index : tcp4_established_node.index);
  return sparse_vec_validate (rt->next_index_by_dst_port,
                              clib_host_to_net_u16 (port));
}

u32
tcp_register_listener (tcp_listener_registration_t * r)
{
  tcp_main_t * tm = vnet_get_tcp_main ();
  tcp_session_t * listener;

  pool_get(tm->listener_pool, listener);
  memset(listener, 0, sizeof(*listener));

  listener->s_t_index = listener - tm->listener_pool;
  listener->s_lcl_port = r->port;

  if (r->is_ip4)
    listener->s_lcl_ip4.as_u32 = r->ip_address.ip4.as_u32;
  else
    clib_memcpy (&listener->s_lcl_ip6, &r->ip_address.ip6,
                 sizeof(ip6_address_t));
  return listener - tm->listener_pool;
}

void
tcp_unregister_listener (u32 listener_index)
{
  tcp_main_t * tm = vnet_get_tcp_main ();
  pool_put_index (tm->listener_pool, listener_index);
}

clib_error_t *
tcp_lookup_init (vlib_main_t * vm)
{
  clib_error_t * error = 0;
  tcp_main_t *tm = vnet_get_tcp_main ();
  f64 log2 = .69314718055994530941;

  if ((error = vlib_call_init_function(vm, ip4_lookup_init)))
    return error;
  if ((error = vlib_call_init_function(vm, ip6_lookup_init)))
    return error;

  /* Initialize dispatch table. */
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
  /* ACK for for a SYN-ACK -> tcp-establish. */
  _(SYN_RCVD, TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISH, TCP_ERROR_NONE);
  /* ACK for for established connection -> tcp-established. */
  _(ESTABLISHED, TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  /* FIN for for established connection -> tcp-established. */
  _(ESTABLISHED, TCP_FLAG_FIN, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
#undef _

  /* Initialize clocks per tick for TCP timestamp. Used to compute
   * monotonically increasing timestamps. */
  tm->log2_tstamp_clocks_per_tick = flt_round_nearest (
      log (TCP_TSTAMP_RESOLUTION / vm->clib_time.seconds_per_clock) / log2);
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
