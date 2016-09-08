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

typedef CLIB_PACKED(struct
{
  /* 16 octets */
  ip4_address_t src;
  ip4_address_t dst;
  u16 src_port;
  u16 dst_port;
  u32 unused_for_now;
}) tcp4_session_key_t;

typedef CLIB_PACKED(struct
{
  /* 48 octets */
  ip6_address_t src;
  ip6_address_t dst;
  u16 src_port;
  u16 dst_port;
  u8 unused_for_now [12];
}) tcp6_session_key_t;

/* Provisionally assume 32-bit timers */
typedef u32 tcp_timer_t;

typedef struct 
{
  u32 his, ours;
} tcp_sequence_pair_t;

#define foreach_tcp_state                               \
_(BOGUS)                                                \
_(ACK_WAIT)  /* sent SYN, wait for ACK/RST */           \
 _(SYNACK_WAIT) /* sent SYN-ACK, wait for ACK */        \
/* and so forth */

typdef enum
{
#define _(s) TCP_STATE_##s,
  foreach_tcp_state
#undef _
} tcp_state_t;

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
  u8 tos, ttl;
  u8 worker_thread_index;

  /* 
   * Shared (or pvt) memory fifos 
   * Almost certainly not part of tcp
   */
  vnet_fifo_t * tx_fifo_index;
  vnet_fifo_t * rx_fifo_index;
  
  tcp_rtt_stats_t stats;
  
  /* 
   * At high scale, pre-built (src,dst,src-port,dst-port) 
   * headers would chew a ton of memory. Maybe worthwile for
   * a few high-throughput flows
   */
  u32 rewrite_template_index;

  u16 src_port, dst_port;
}) tcp46_session_t;

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

typedef enum
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
typedef struct _tcp_work_queue
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

typedef struct
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

typedef struct
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

typedef struct
{
  /* Per-worker thread connection pools */
  tcp4_session_t **ip4_sessions;
  tcp6_session_t **ip6_sessions;

  /* Per-worker thread timer vectors, parallel to connection pools */
  tcp_timer_t **timers;

  /* Non-packet work queues */
  tcp_work_queue_t **rx_work_queues;

  /* Connections to peer processes */
  tcp_peer_connection * peer_connections;

  /* bind table vector $$$ sparse vector $$$ */
  tcp_bind_table_entry_t * bind_table;
  
  /* Per-worker ip4 session lookup tables */
  clib_bihash_16_4_t **ip4_lookup_tables;

  /* Per-worker ip6 session lookup tables */
  clib_bihash_48_4_t **ip6_lookup_tables;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ip4_main_t * ip4_main;
  ip6_main_t * ip6_main;
} tcp_main_t;


#endif /* _vnet_tcp_h_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
