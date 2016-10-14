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
#ifndef __included_uri_db_h__
#define __included_uri_db_h__

#include <vlibmemory/unix_shared_memory_queue.h>
#include <vlibmemory/api.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/sparse_vec.h>
#include <svm_fifo_segment.h>
#include <vnet/uri/udp_session.h>

/** @file
    URI-related database
    
    Session lookup key; (src-ip, dst-ip, src-port, dst-port, tcp/udp)
    Value: (owner thread index << 32 | session_index);

    it's probably a bad idea to hang onto buffers waiting for the
    server to accept the connection. Be optimistic, set up, and
    be willing to flush the work.
*/

typedef enum 
{
  FIFO_EVENT_SERVER_RX,
  FIFO_EVENT_SERVER_TX,
  FIFO_EVENT_TIMEOUT,
  FIFO_EVENT_SERVER_EXIT,
} fifo_event_type_t;

/* Event queue input node static next indices */
typedef enum {
  URI_QUEUE_NEXT_DROP,
  URI_QUEUE_NEXT_IP4_LOOKUP,
  URI_QUEUE_NEXT_IP6_LOOKUP,
  URI_QUEUE_N_NEXT,
} uri_queue_next_t;

#define foreach_uri_session_type                \
  _(IP4_TCP, ip4_tcp)                           \
  _(IP4_UDP, ip4_udp)                           \
  _(IP6_TCP, ip6_tcp)                           \
  _(IP6_UDP, ip6_udp)                           \
  _(FIFO, fifo)

typedef enum
{
#define _(A, a) SESSION_TYPE_##A,
  foreach_uri_session_type
#undef _
  SESSION_TYPE_N_TYPES,
} stream_session_type_t;

/* 
 * Epic catalog of all session states from all session types 
 */
typedef enum
{
  SESSION_STATE_CONNECTING,
  SESSION_STATE_READY,
} stream_session_state_t;

typedef CLIB_PACKED(struct
{
  svm_fifo_t * fifo;
  u8 event_type;
  /* $$$$ for event logging */
  u16 event_id;
  u16 enqueue_length;
}) fifo_event_t;

typedef clib_bihash_kv_16_8_t session_key_t;

typedef struct
{
  /** fifo pointers. Once allocated, these do not move */
  svm_fifo_t * server_rx_fifo;
  svm_fifo_t * server_tx_fifo;

  /** tcp | udp */
  u8 is_tcp;
  u8 session_thread_index;
  /** To avoid n**2 "one event per frame" check */
  u8 enqueue_epoch;

  /** used during unbind processing */
  u8 is_deleted;

  /** Type */
  u8 session_type;

  /** State */
  u8 session_state;

  /** Session index in per_thread pool */
  u32 session_index;

  /** stream server pool index */
  u32 server_index;

  /** svm segment index */
  u32 server_segment_index;

  /** index into transport specific pool */
  u32 transport_connection_index;

  /** transport computed session key */
  session_key_t session_key;

//  union
//  {
//    udp4_session_t u4;
//    /* udp6_session_t u6 */
//    /* tcp4_session_t t4; */
//    /* tcp4_session_t t6; */
//  };
} stream_session_t;

struct _stream_server_main;

typedef struct _stream_server
{
  /** segments mapped by this server */
  u32 * segment_indices;

  /** Server listens for events on this svm queue */
  unix_shared_memory_queue_t *event_queue;

  /** Binary API connection index, ~0 if internal */
  u32 api_client_index;
  
  /** Accept cookie, for multiple session flavors ($$$ maybe) */
  u32 accept_cookie;

  /** Shoulder-taps for the server */
  int (*session_create_callback) (struct _stream_server *server, 
                                  stream_session_t *new_session,
                                  unix_shared_memory_queue_t *vpp_event_queue);
  /* Rejected session callback */
  void (*session_delete_callback) (struct _stream_server_main *ssm,
                                   stream_session_t *session);
  /* Existing session delete callback */
  void (*session_clear_callback) (struct _stream_server_main *ssm,
                                  struct _stream_server *server,
                                  stream_session_t *session);
  /* Direct RX callback, for built-in servers */
  void (*builtin_server_rx_callback)(struct _stream_server_main *ssm,
                                     struct _stream_server *server,
                                     stream_session_t *session);
} stream_server_t;

typedef struct _stream_server_main
{
  /** Lookup tables */
  clib_bihash_16_8_t v4_session_hash;

  clib_bihash_48_8_t v6_session_hash;

  /** per worker thread session pools */
  stream_session_t **sessions;
  
  /* Server pool */
  stream_server_t * servers;

  /** Sparse vector to map dst port to stream server  */
  u16 * stream_server_by_dst_port[SESSION_TYPE_N_TYPES];

  /** per-worker enqueue epoch counters */
  u8 * current_enqueue_epoch;

  /** Per-worker thread vector of sessions to enqueue */
  u32 **session_indices_to_enqueue_by_thread;

  /** per-worker tx buffer free lists */
  u32 ** tx_buffers;

  /** per-worker active event vectors */
  fifo_event_t ** fifo_events;

  /** per-worker built-in server copy buffers */
  u8 **copy_buffers;

  /** vpp fifo event queue */
  unix_shared_memory_queue_t **vpp_event_queues;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} stream_server_main_t;

extern stream_server_main_t stream_server_main;
extern vlib_node_registration_t udp4_uri_input_node;
extern vlib_node_registration_t tcp4_uri_input_node;
extern vlib_node_registration_t tcp6_uri_input_node;

stream_session_t *
v4_stream_session_create (stream_server_main_t *ssm, stream_server_t * ss,
                          stream_session_type_t session_type,
                          clib_bihash_kv_16_8_t session_key,
                          u32 connection_index, int my_thread_index);
void
v4_stream_session_delete (stream_server_main_t *ssm, stream_session_t * s);

stream_session_t *
v6_stream_session_create (stream_server_main_t *ssm, stream_server_t * ss,
                          stream_session_type_t session_type,
                          clib_bihash_kv_48_8_t session_key,
                          u32 connection_index, int my_thread_index);

always_inline int
check_api_queue_full (stream_server_t *ss)
{
  unix_shared_memory_queue_t * q;

  /* builtin servers are always OK */
  if (ss->api_client_index == ~0)
    return 0;

  q = vl_api_client_index_to_input_queue (ss->api_client_index);
  if (!q)
    return 1;

  if (q->cursize == q->maxsize)
    return 1;
  return 0;
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_uri_db_h__ */