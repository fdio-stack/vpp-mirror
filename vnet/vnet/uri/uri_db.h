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
#include "udp_session.h"
#include <vppinfra/sparse_vec.h>

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
} fifo_event_t;

typedef CLIB_PACKED(struct
{
  svm_fifo_t * fifo;
  u8 event_type;
}) fifo_event;

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
  u8 pad[1];

  /** stream server pool index */
  u32 server_index;

  /** svm segment index */
  u32 server_segment_index;

  /*
   * Nobody in their right mind uses a stream abstraction for udp.
   * We start w/ udp to debug the infra...
   */
  union 
  {
    udp4_session_t u4;
    /* udp6_session_t u6 */
    /* tcp4_session_t t4; */
    /* tcp4_session_t t6; */
  };
} stream_session_t;

typedef struct _stream_server
{
  /** Vector of svm segments mapped by this server */
  svm_fifo_segment_private_t *segments;

  /** Server listens for events on this svm queue */
  unix_shared_memory_queue_t *event_queue;

  /** Binary API connection index, ~0 if internal */
  u32 api_client_index;
  
  /** Shoulder-tap the server */
  void (*session_create_callback) (struct _stream_server *server, 
                                   stream_session_t *new_session);
} stream_server_t;

typedef struct
{
  /** Lookup tables */
  clib_bihash_16_8_t v4_session_hash;

  // clib_bihash_48_8_t v6_session_hash;

  /** per worker thread session pools */
  stream_session_t **sessions;
  
  /* Server pool */
  stream_server_t * servers;

  /** Sparse vector to map dst port to stream server  */
  u16 * stream_server_by_dst_port;

  /** per-worker enqueue epoch counters */
  u8 * current_enqueue_epoch;

  /** Per-worker thread vector of sessions to enqueue */
  u32 **sessions_indices_to_enqueue_by_thread;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} stream_server_main_t;

extern stream_server_main_t stream_server_main;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_uri_db_h__ */
