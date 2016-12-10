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

#ifndef _vnet_tcp_h_
#define _vnet_tcp_h_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/uri/transport.h>
#include <vnet/uri/uri.h>

#define MAX_HDRS_LEN 100
#define TCP_TSTAMP_RESOLUTION 1e-3
#define TCP_PAWS_IDLE 24 * 24 * 60 * 60 / TCP_TSTAMP_RESOLUTION /* 24 days */
#define TCP_MAX_OPTION_SPACE 40

/* Provisionally assume 32-bit timers */
typedef u32 tcp_timer_t;

/** TCP FSM state definitions as per RFC793. */
#define foreach_tcp_fsm_state   \
  _(CLOSED, "CLOSED")           \
  _(LISTEN, "LISTEN")           \
  _(SYN_SENT, "SYN_SENT")       \
  _(SYN_RCVD, "SYN_RCVD")       \
  _(ESTABLISHED, "ESTABLISHED") \
  _(CLOSE_WAIT, "CLOSE_WAIT")   \
  _(FIN_WAIT_1, "FIN_WAIT_1")   \
  _(LAST_ACK, "LAST_ACK")       \
  _(CLOSING, "CLOSING")         \
  _(FIN_WAIT_2, "FIN_WAIT_2")   \
  _(TIME_WAIT, "TIME_WAIT")

typedef enum _tcp_fsm_states
{
#define _(sym, str) TCP_CONNECTION_STATE_##sym,
  foreach_tcp_fsm_state
#undef _
  TCP_N_CONNECTION_STATE
} tcp_fsm_states_t;

format_function_t format_tcp_state;

typedef struct
{
  /* sum, sum**2 */
  f64 sum, sum_sq;
  f64 count;
} tcp_rtt_stats_t;

typedef struct _tcp_session
{
  transport_session_t session;          /** must be first */

  /* our timer is in the dense parallel vector */
  tcp_timer_t remote_timestamp_net_byte_order;

  u8 state;   /* tcp_state_t */

  /* TODO RFC4898 */

  /** Send sequence variables RFC793*/
  u32 snd_una;          /**< oldest unacknowledged sequence number */
  u16 snd_wnd;          /**< send window */
  u32 snd_wl1;          /**< seq number used for last snd.wnd update */
  u32 snd_wl2;          /**< ack number used for last snd.wnd update */
  u32 snd_nxt;          /**< next seq number to be sent */

  /** Receive sequence variables RFC793 */
  u32 rcv_nxt;          /**< next sequence number expected */
  u32 rcv_wnd;          /**< receive window we expect */

  u32 rcv_las;          /**< rcv_nxt at last ack sent/rcv_wnd update */

  tcp_options_t opt;    /**< send/receive and session options */

  u32 iss;              /**< initial sent sequence */
  u32 irs;              /**< initial remote sequence */

  /* Options */
  u8 rcv_wscale;        /**< Window scale to advertise to peer */
  u8 snd_wscale;        /**< Window scale to use when sending */
  u32 tsval_recent;     /**< last timestamp received */
  u32 tsval_recent_age; /**< when last updated tstamp_recent*/

  u16 max_segment_size;
  u8 remote_window_scale;
  u8 local_window_scale;

  u32 n_tx_unacked_bytes;

  /* Set if connected to another tcp46_session_t */
  u32 connected_session_index;

  u16 flags;

  /* tos, ttl to use on tx */
  u8 tos;
  u8 ttl;
  u8 worker_thread_index;

  tcp_rtt_stats_t stats;

  /*
   * At high scale, pre-built (src,dst,src-port,dst-port)
   * headers would chew a ton of memory. Maybe worthwile for
   * a few high-throughput flows
   */
  u32 rewrite_template_index;
} tcp_session_t;

typedef enum {
  TCP_IP4,
  TCP_IP6,
  TCP_N_AF,
} tcp_af_t;

typedef enum _tcp_error
{
#define tcp_error(n,s) TCP_ERROR_##n,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
  TCP_N_ERROR,
} tcp_error_t;

typedef struct tcp_listener
{
  /* Bitmap indicating which of local (interface) addresses
   we should listen on for this destination port. */
  uword * valid_local_adjacency_bitmap;

  /* Destination port to listen for connections. */
  u16 dst_port;

  u16 next_index[TCP_N_AF];

  u32 flags;

  /* Connection indices for which event in event_function applies to. */
  u32 * event_connections[TCP_N_AF];
  u32 * eof_connections[TCP_N_AF];
  u32 * close_connections[TCP_N_AF];

//  tcp_event_function_t * event_function;
} tcp_listener_t;

typedef struct tcp_listener_registration
{
  /* Listen on this port. */
  u16 port;

  /* Listen at this addresses */
  ip46_address_t ip_address;

  u8 is_ip4;
  /* TODO options? */
} tcp_listener_registration_t;

typedef struct {
  u8 next, error;
} tcp_lookup_dispatch_t;

u32
tcp_register_listener (tcp_listener_registration_t * r);
void
tcp_unregister_listener (u32 listener_index);

typedef struct _tcp_main
{
  /* Per-worker thread tcp connection pools */
  tcp_session_t **sessions;

  /* Per-worker thread timer vectors, parallel to connection pools */
  tcp_timer_t **timers;

  /* Hash tables mapping name/protocol to protocol info index. */
  uword * dst_port_info_by_name[TCP_N_AF];
  uword * dst_port_info_by_dst_port[TCP_N_AF];

  /* Pool of listeners. */
  tcp_session_t *listener_pool;

  u32 *listener_index_by_dst_port;

  /** Dispatch table by state and flags */
  tcp_lookup_dispatch_t dispatch_table[TCP_N_CONNECTION_STATE][64];

  u8 log2_tstamp_clocks_per_tick;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ip4_main_t * ip4_main;
  ip6_main_t * ip6_main;
} tcp_main_t;

tcp_main_t tcp_main;

extern vlib_node_registration_t tcp4_output_node;
extern vlib_node_registration_t tcp6_output_node;

always_inline tcp_main_t *
vnet_get_tcp_main ()
{
  return &tcp_main;
}

always_inline tcp_session_t *
tcp_session_get (u32 tsi, u32 thread_index)
{
  return pool_elt_at_index(tcp_main.sessions[thread_index], tsi);
}

always_inline tcp_session_t *
tcp_listener_get (u32 tsi)
{
  return pool_elt_at_index(tcp_main.listener_pool, tsi);
}

void
tcp_send_ack (tcp_session_t *ts, u8 is_ip4);
void
tcp_send_synack (tcp_session_t *ts, u8 is_ip4);
void
tcp_send_dupack (tcp_session_t *ts, u8 is_ip4);
void
tcp_send_challange_ack (tcp_session_t *ts, u8 is_ip4);
void
tcp_send_reset (vlib_buffer_t *pkt, u8 is_ip4);

always_inline u32
tcp_end_seq (tcp_header_t *th, u32 len)
{
  return th->seq_number + tcp_is_syn(th) + tcp_is_fin(th) + len;
}

/* Modulo arithmetic for TCP sequence numbers */
#define seq_lt(_s1, _s2) ((i32)((_s1)-(_s2)) < 0)
#define seq_leq(_s1, _s2) ((i32)((_s1)-(_s2)) <= 0)
#define seq_gt(_s1, _s2) ((i32)((_s1)-(_s2)) > 0)
#define seq_geq(_s1, _s2) ((i32)((_s1)-(_s2)) >= 0)


/* Modulo arithmetic for timestamps */
#define timestamp_lt(_t1, _t2) ((i32)((_t1)-(_t2)) < 0)
#define timestamp_leq(_t1, _t2) ((i32)((_t1)-(_t2)) <= 0)

/**
 * Compute actual receive window. Peer might have pushed more data than our
 * window since the last ack we sent, in which case, receive window is 0.
 */
always_inline u32
tcp_actual_receive_window (const tcp_session_t *ts)
{
  i32 rcv_wnd = ts->rcv_wnd + ts->rcv_las - ts->rcv_nxt;
  if (rcv_wnd < 0)
    rcv_wnd = 0;
  return (u32) rcv_wnd;
}

always_inline u32
tcp_snd_wnd_end (const tcp_session_t *ts)
{
  return ts->snd_una + ts->snd_wnd;
}

always_inline u32
tcp_time_now (void)
{
  return clib_cpu_time_now () >> tcp_main.log2_tstamp_clocks_per_tick;
}

always_inline void
tcp_session_delete (u32 session_index, u32 my_thread_index)
{
  pool_put_index(tcp_main.sessions[my_thread_index], session_index);
}

u32
tcp_uri_tx_packetize_ip4 (vlib_main_t *vm, stream_session_t *s,
                          vlib_buffer_t *b);
u32
tcp_uri_tx_packetize_ip6 (vlib_main_t *vm, stream_session_t *s,
                          vlib_buffer_t *b);

#endif /* _vnet_tcp_h_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
