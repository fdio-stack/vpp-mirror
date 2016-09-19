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

/** @file
    udp state machine, etc.
*/

#include "uri_db.h"

/** Create a session, ping the server by callback */
stream_session_t *
v4_stream_session_create (stream_server_main_t *ssm, 
                          stream_server_t * ss, 
                          udp4_session_key_t * key0,
                          int my_thread_index, is_tcp)
{
  clib_bihash_kv_16_8_t kv0;
  svm_fifo_t * server_rx_fifo, * server_tx_fifo;
  svm_fifo_segment_private_t * fifo_segment;
  stream_session_t * s;
  u32 pool_index;

  ASSERT (ss->segments);

  /* $$$ better allocation policy? */
  fifo_segment = vec_elt_at_index(ss->segments, vec_len(ss->segments)-1);

  /* $$$ size policy */
  server_rx_fifo = svm_fifo_segment_alloc_fifo 
    (fifo_segment, 8192);

  /* $$$ callback to map another segment */
  ASSERT(server_rx_fifo);

  server_tx_fifo = svm_fifo_segment_alloc_fifo 
    (fifo_segment, 8192);

  ASSERT(server_tx_fifo);
  
  pool_get (ssm->sessions[my_thread_index], s);
  memset (s, 0, sizeof (*s));

  /* Initialize backpointers */
  pool_index = s - ssm->sessions[my_thread_index];
  server_rx_fifo->server_session_index = pool_index;
  server_rx_fifo->server_thread_index = my_thread_index;

  server_tx_fifo->server_session_index = pool_index;
  server_rx_fifo->server_segment_index = fifo_segment - ss->segments;

  
  /* Initialize state machine, such as it is... */
  s->session_type = is_tcp ? SESSION_TYPE_IP4_TCP : SESSION_TYPE_IP4_UDP;
  s->state = SESSION_STATE_CONNECTING;
  s->u4.mtu = 1024;             /* $$$$ policy */
  s->key.as_u64[0] = key0->as_u64[0];
  s->key.as_u64[1] = key0->as_u64[1];

  s->server_index = ss - ssm->servers;
  s->server_segment_index = fifo_segment - ss->segments;
  s->session_thread_index = my_thread_index;

  kv0.key.as_u64[0] = key0->as_u64[0];
  kv0.key.as_u64[1] = key0->as_u64[1];
  kv0.value = (((u64) my_thread_index) << 32) | (u64) pool_index;

  /* Add to the main lookup table */
  clib_bihash_16_8_add_del (ssm->v4_session_hash, &kv0, 1 /* is_add */);

  /* Shoulder-tap the registered server */
  ss->session_create_callback (ss, s);
  return (s);
}

int v4_stream_session_delete (stream_server_main_t *ssm, 
                              stream_session_t * s)
{
  clib_bihash_kv_16_8_t kv0;
  int rv;
  stream_server_t * ss, 
  svm_fifo_segment_private_t * fifo_segment;
  
  kv0.key.as_u64[0] = s->key.as_u64[0];
  kv0.key.as_u64[1] = s->key.as_u64[1];
  kv0.value = ~0ULL;

  /* delete from the main lookup table */
  rv = clib_bihash_16_8_add_del (ssm->v4_session_hash, &kv0, 0 /* is_add */);
  
  if (rv)
    clib_warning ("hash delete error, rv %d", rv);

  /* Recover the server from the session */
  ss = pool_elt_at_index (ssm->segments, s->server_index);

  /* And the fifo segment from the server */
  fifo_segment = vec_elt_at_index (ss->segments, s->server_segment_index);

  svm_fifo_segment_free_fifo (fifo_segment, s->server_rx_fifo);
  svm_fifo_segment_free_fifo (fifo_segment, s->server_tx_fifo);

  pool_put (ssm->sessions[s->my_thread_index], s);
  
  return rv;
}

int vnet_bind_udp4_uri (vnet_bind_uri_args_t * a)
{
  uri_main_t * um = &uri_main;
  api_main_t *am = &api_main;
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  stream_server_main_t * ssm = &stream_server_main;
  stream_server_t * ss;
  fifo_bind_table_entry_t * e;
  vl_api_registration_t *regp;
  uword * p;
  u8 * server_name, * segment_name;
  void * oldheap;

  ASSERT(segment_name_length);

  p = hash_get_mem (um->fifo_bind_table_entry_by_name, uri);

  if (p)
    return VNET_API_ERROR_ADDRESS_IN_USE;

  /* External client? */
  if (a->api_client_index != ~0)
    {
      regp = vl_api_client_index_to_registration (a->api_client_index);
      ASSERT(regp);
      server_name = format (0, "%s%c", regp->name, 0);
    }
  else
    server_name = format (0, "<internal>%c", 0);

  /* 
   * $$$$ lookup client by api client index, to see if we're already
   * talking to this client about some other port
   */

  /* Unique segment name, per vpp instance */
  segment_name = format (0, "%d-%s%c", getpid(), uri, 0);
  ASSERT (vec_len(segment_name) <= 128);
  *a->segment_name_length = vec_len(segment_name);
  memcpy (a->segment_name, segment_name, *a->segment_name_length);

  ca->segment_name = segment_name;
  ca->segment_size = segment_size;

  rv = svm_fifo_segment_create (ca);
  if (rv)
    {
      clib_warning ("sm_fifo_segment_create ('%s', %d) failed",
                    segment_name, segment_size);
      return VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
    }

  pool_get (ssm->servers, ss);
  memset (ss, 0, sizeof (*ss));

  /* Allocate event fifo in the /vpe-api shared-memory segment */
  oldheap = svm_push_data_heap (am->vlib_rp);

  /* Allocate vpp event queue (once) */
  if (ssm->vpp_event_queue == 0)
    {
      ssm->vpp_event_queue = unix_shared_memory_queue_init 
        (2048 /* nels $$$$ config */, 
         sizeof (fifo_event_t),
         0 /* consumer pid */,
         0 /* (do not) send signal when queue non-empty */);
    }

  /* Allocate server event queue */
  if (ss->event_queue == 0)
    {
      ss->event_queue = unix_shared_memory_queue_init 
        (128 /* nels $$$$ config */, 
         sizeof (fifo_event_t),
         0 /* consumer pid */,
         0 /* (do not) send signal when queue non-empty */);
    }
  svm_pop_heap (oldheap);

  a->vpp_event_queue_address = ssm->vpp_event_queue;
  a->server_event_queue_address = (u64) ss->event_queue;

  ss->session_create_callback = session_create_callback_arg;
  ss->session_delete_callback = v4_stream_session_delete;
  ss->api_client_index = api_client_index;

  hash_set_mem (um->fifo_bind_table_entry_by_name, e->fifo_name, 
                e - um->fifo_bind_table);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
