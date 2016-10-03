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

typedef CLIB_PACKED(struct
{
  union
  {
    struct
    {
      /* 16 octets */
      ip4_address_t src;
      ip4_address_t dst;
      u16 src_port;
      u16 dst_port;
      u32 session_type;
    };
    u64 as_u64[2];
  };
}) tcp4_session_key_t;

typedef CLIB_PACKED(struct
{
  /* 48 octets */
  ip6_address_t src;
  ip6_address_t dst;
  u16 src_port;
  u16 dst_port;
  u32 session_type;
  u8 unused_for_now [8];
}) tcp6_session_key_t;

/* Provisionally assume 32-bit timers */
typedef u32 tcp_timer_t;

typedef struct 
{
  u32 his, ours;
} tcp_sequence_pair_t;

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
#define _(sym, str) TCP_STATE_##sym,
  foreach_tcp_fsm_state
#undef _
  TCP_N_STATE
} tcp_fsm_states_t;

format_function_t format_tcp_state;

typedef struct 
{
  /* sum, sum**2 */
  f64 sum, sum_sq;
  f64 count;
} tcp_rtt_stats_t;

typedef CLIB_PACKED(struct 
{
  tcp_sequence_pair_t sequence_numbers;

  /* our timer is in the dense parallel vector */
  tcp_timer_t his_timestamp_net_byte_order;

  u16 max_segment_size;
  u16 his_window;
  u16 my_window;
  u8 his_window_scale;
  u8 my_window_scale;

  u32 n_tx_unacked_bytes;

  /* Set if connected to another tcp46_session_t */
  u32 connected_session_index;

  /* This session is ip6 */
  u8 is_ip6;
  /* 4-6, 6-4 connections are possible, separate pools */
  u8 connected_to_ip6;

  u16 flags;

  u8 state;   /* tcp_state_t */

  /* tos, ttl to use on tx */
  u8 tos;
  u8 ttl;
  u8 worker_thread_index;

//  /*
//   * Shared (or pvt) memory fifos
//   * Almost certainly not part of tcp
//   */
//  vnet_fifo_t * tx_fifo_index;
//  vnet_fifo_t * rx_fifo_index;

  tcp_rtt_stats_t stats;

  /*
   * At high scale, pre-built (src,dst,src-port,dst-port)
   * headers would chew a ton of memory. Maybe worthwile for
   * a few high-throughput flows
   */
  u32 rewrite_template_index;

  u16 src_port;
  u16 dst_port;
}) tcp46_session_t;

typedef enum {
  TCP_IP4,
  TCP_IP6,
  TCP_N_AF,
} tcp_af_t;

typedef CLIB_PACKED(struct
{
  tcp46_session_t s;
  ip4_address_t src_address;
  ip4_address_t dst_address;
}) tcp4_session_t;

typedef CLIB_PACKED(struct
{
  tcp46_session_t s;
  ip6_address_t src_address;
  ip6_address_t dst_address;
}) tcp6_session_t;

typedef enum _tcp_wq_entry_type
{
  TCP_WQ_TIMER_EXPIRED,
  TCP_WQ_TX_FIFO_DATA_ADDED,
  TCP_WQ_TX_FIFO_DATA_REMOVED,
  TCP_WQ_RX_FIFO_DATA_ADDED,
  TCP_WQ_RX_FIFO_DATA_REMOVED,
} tcp_wq_entry_type_t;

/* 
 * These things are sent bidirectionally. 
 */
typedef struct _tcp_work_queue_entry
{
  union 
  {
    struct 
    {
      u32 session_index;
      tcp_wq_entry_type_t type;
    };
    u64 as_u64;
    struct _tcp_work_queue * next_free;
  };
} tcp_work_queue_entry_t;

typedef struct _tcp_work_queue
{
  volatile u32 lock;
  /* 
   * Buffer trading. When the work queue processor
   * decides to process entries: grab lock, steal entry vector,
   * replace with entry from freelist [if available], drop lock.
   */
  tcp_work_queue_entry_t * entries;
  tcp_work_queue_entry_t * freelist;
} tcp_work_queue_t;

typedef struct _tcp_bind_table_entry
{
  /* 0 if vpp built-in server */
  pid_t owner_pid;
  u32 client_index;
  /* vpp built-in server */
  void * callback;
  u8 is_ipv6;
  u8 mask_width;
  /* 80, 443, yadda yadda */
  u16 dst_port;
  union {
    ip4_address_t ip4;
    ip6_address_t ip6;
  };
} tcp_bind_table_entry_t;

typedef enum _tcp_error
{
#define tcp_error(n,s) TCP_ERROR_##n,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
  TCP_N_ERROR,
} tcp_error_t;

#define foreach_tcp4_dst_port                   \
_ (4342, lisp_cp)

#define foreach_tcp6_dst_port                   \
_ (4342, lisp_cp6)

typedef enum _tcp_dst_port
{
#define _(n,f) TCP_DST_PORT_##f = n,
  foreach_tcp4_dst_port
  foreach_tcp6_dst_port
#undef _
} tcp_static_dst_port_t;

//typedef struct _tcp_dst_port_info
//{
//  /* Name (a c string). */
//  char * name;
//
//  /* host byte order. */
//  tcp_dst_port_t dst_port;
//
//  /* Node which handles this type. */
//  u32 node_index;
//
//  /* Next index for this type. */
//  u32 next_index;
//} tcp_dst_port_info_t;

#define foreach_tcp_event                                       \
  /* Received a SYN-ACK after sending a SYN to connect. Or
   * received an ACK after sending a SYN-ACK */                 \
  _ (connection_established)                                    \
  /* Received a RST from a non-established connection. */       \
  _ (connect_failed)                                            \
  /* Received a FIN from an established connection. */          \
  _ (fin_received)                                              \
  _ (connection_closed)                                         \
  /* Received a RST from an established connection. */          \
  _ (reset_received)

typedef enum _tcp_event_type
{
#define _(f) TCP_EVENT_##f,
  foreach_tcp_event
#undef _
} tcp_event_type_t;

typedef void
(tcp_event_function_t) (u32 * connections, tcp_event_type_t event_type);

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

  tcp_event_function_t * event_function;
} tcp_listener_t;

typedef struct tcp_listener_registration
{
  /* Listen on this port. */
  u16 port;

#define TCP_LISTENER_IP4 (1 << 0)
#define TCP_LISTENER_IP6 (1 << 1)
  u16 flags;

  /* Next node index for data packets. */
  u32 data_node_index;

  /* Event function: called on new connections */
  tcp_event_function_t * event_function;
} tcp_listener_registration_t;

uword
tcp_register_listener (vlib_main_t * vm, tcp_listener_registration_t * r);

typedef struct _tcp_main
{
  /* Per-worker thread connection pools */
  tcp4_session_t **ip4_sessions;
  tcp6_session_t **ip6_sessions;

  /* Per-worker thread timer vectors, parallel to connection pools */
  tcp_timer_t **timers;

  /* Non-packet work queues */
  tcp_work_queue_t **rx_work_queues;

  /* Connections to peer processes */
//  tcp_peer_connection_t * peer_connections;

  /* bind table vector $$$ sparse vector $$$ */
  tcp_bind_table_entry_t * bind_table;

  /* Per-worker ip4 session lookup tables */
//  clib_bihash_16_4_t **ip4_lookup_tables;

  /* Per-worker ip6 session lookup tables */
//  clib_bihash_48_4_t **ip6_lookup_tables;

  /* Hash tables mapping name/protocol to protocol info index. */
  uword * dst_port_info_by_name[TCP_N_AF];
  uword * dst_port_info_by_dst_port[TCP_N_AF];

  /* Pool of listeners. */
  tcp_listener_t *listener_pool;
  u32 *listener_index_by_dst_port;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ip4_main_t * ip4_main;
  ip6_main_t * ip6_main;
} tcp_main_t;

tcp_main_t tcp_main;

always_inline tcp_main_t *
vnet_get_tcp_main ()
{
  return &tcp_main;
}

#endif /* _vnet_tcp_h_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
