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

#include "uri.h"
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/udp.h>
#include <vppinfra/sparse_vec.h>

/** Create a session, ping the server by callback */
stream_session_t *
v4_stream_session_create (stream_server_main_t *ssm, 
                          stream_server_t * ss, 
                          udp4_session_key_t * key0,
                          int my_thread_index, int is_tcp)
{
  clib_bihash_kv_16_8_t kv0;
  svm_fifo_t * server_rx_fifo, * server_tx_fifo;
  svm_fifo_segment_private_t * fifo_segment;
  stream_session_t * s;
  u32 pool_index;
  u32 fifo_segment_index;
  unix_shared_memory_queue_t * vpp_event_queue;

  /* $$$ better allocation policy? */
  ASSERT (vec_len(ss->segment_indices));
  fifo_segment_index = ss->segment_indices[vec_len(ss->segment_indices)-1];
  fifo_segment = svm_fifo_get_segment (fifo_segment_index);

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
  server_tx_fifo->server_thread_index = my_thread_index;

  s->server_rx_fifo = server_rx_fifo;
  s->server_tx_fifo = server_tx_fifo;
  
  /* Initialize state machine, such as it is... */
  s->u4.session_type = is_tcp ? SESSION_TYPE_IP4_TCP : SESSION_TYPE_IP4_UDP;
  s->u4.state = SESSION_STATE_CONNECTING;
  s->u4.mtu = 1024;             /* $$$$ policy */
  s->u4.key.as_u64[0] = key0->as_u64[0];
  s->u4.key.as_u64[1] = key0->as_u64[1];

  s->server_index = ss - ssm->servers;
  s->server_segment_index = fifo_segment_index;
  s->session_thread_index = my_thread_index;
  s->session_index = pool_index;

  kv0.key[0] = key0->as_u64[0];
  kv0.key[1] = key0->as_u64[1];
  kv0.value = (((u64) my_thread_index) << 32) | (u64) pool_index;

  /* Add to the main lookup table */
  clib_bihash_add_del_16_8 (&ssm->v4_session_hash, &kv0, 1 /* is_add */);

  vpp_event_queue = ssm->vpp_event_queues[my_thread_index];

  /* Shoulder-tap the registered server */
  ss->session_create_callback (ss, s, vpp_event_queue);
  return (s);
}

void v4_stream_session_delete (stream_server_main_t *ssm, 
                              stream_session_t * s)
{
  clib_bihash_kv_16_8_t kv0;
  int rv;
  svm_fifo_segment_private_t * fifo_segment;
  u32 my_thread_index = ssm->vlib_main->cpu_index;
  
  kv0.key[0] = s->u4.key.as_u64[0];
  kv0.key[1] = s->u4.key.as_u64[1];
  kv0.value = ~0ULL;

  /* delete from the main lookup table */
  rv = clib_bihash_add_del_16_8 (&ssm->v4_session_hash, &kv0, 0 /* is_add */);
  
  if (rv)
    clib_warning ("hash delete error, rv %d", rv);

  /* recover the fifo segment */
  fifo_segment = svm_fifo_get_segment (s->server_segment_index);

  svm_fifo_segment_free_fifo (fifo_segment, s->server_rx_fifo);
  svm_fifo_segment_free_fifo (fifo_segment, s->server_tx_fifo);

  pool_put (ssm->sessions[my_thread_index], s);
}

int vnet_bind_udp4_uri (vnet_bind_uri_args_t * a)
{
  uri_main_t * um = &uri_main;
  api_main_t *am = &api_main;
  u32 my_thread_index = um->vlib_main->cpu_index;
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  stream_server_main_t * ssm = &stream_server_main;
  stream_server_t * ss;
  vl_api_registration_t *regp;
  uword * p;
  u8 * segment_name;
  u8 * server_name;
  void * oldheap;
  int rv;
  char * cp;
  u32 port_number_host_byte_order;
  fifo_bind_table_entry_t * e;
  u16 * n;

  ASSERT(a->segment_name_length);

  p = hash_get_mem (um->fifo_bind_table_entry_by_name, a->uri);

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

  /* "udp4:12345" */
  cp = &a->uri[5];
  if (*cp == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  port_number_host_byte_order = 0;
  while (*cp != 0 && (*cp >= '0' && *cp <= '9'))
    {
      port_number_host_byte_order = (port_number_host_byte_order<<3) + 
        (port_number_host_byte_order<<1);
      port_number_host_byte_order += *cp - '0';
      cp++;
    }

  if (port_number_host_byte_order > 65535)
    return VNET_API_ERROR_INVALID_VALUE;

  udp_register_dst_port (um->vlib_main, port_number_host_byte_order,
                         udp4_uri_input_node.index,
                         1 /* is_ipv4 */);

  /* 
   * $$$$ lookup client by api client index, to see if we're already
   * talking to this client about some other port
   */

  /* Unique segment name, per vpp instance */
  segment_name = format (0, "%d-%s%c", getpid(), a->uri, 0);
  ASSERT (vec_len(segment_name) <= 128);
  a->segment_name_length = vec_len(segment_name);
  memcpy (a->segment_name, segment_name, a->segment_name_length);

  ca->segment_name = (char *) segment_name;
  ca->segment_size = a->segment_size;

  rv = svm_fifo_segment_create (ca);
  if (rv)
    {
      clib_warning ("sm_fifo_segment_create ('%s', %d) failed",
                    a->segment_name, a->segment_size);
      return VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
    }

  pool_get (ssm->servers, ss);
  memset (ss, 0, sizeof (*ss));

  /* Allocate event fifo in the /vpe-api shared-memory segment */
  oldheap = svm_push_data_heap (am->vlib_rp);

  /* Allocate vpp event queue (once) */
  if (ssm->vpp_event_queues[my_thread_index] == 0)
    {
      ssm->vpp_event_queues[my_thread_index] = unix_shared_memory_queue_init 
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

  a->server_event_queue_address = (u64) ss->event_queue;

  ss->session_create_callback = a->send_session_create_callback;
  ss->session_delete_callback = v4_stream_session_delete;
  ss->api_client_index = a->api_client_index;
  
  vec_add1 (ss->segment_indices, ca->new_segment_index);

  n = sparse_vec_validate (ssm->stream_server_by_dst_port, 
                           clib_host_to_net_u16(port_number_host_byte_order));
  n[0] = (ss - ssm->servers) + 1; /* avoid SPARSE_VEC_INDEX_INVALID */

  pool_get (um->fifo_bind_table, e);
  memset (e, 0, sizeof (*e));

  e->fifo_name = format (0, "%s%c", a->uri, 0);
  e->server_name = server_name;
  e->segment_name = segment_name;
  e->bind_client_index = a->api_client_index;
  e->accept_cookie = a->accept_cookie;

  hash_set_mem (um->fifo_bind_table_entry_by_name, e->fifo_name, 
                e - um->fifo_bind_table);
  return 0;
}

int vnet_unbind_udp4_uri (char *uri, u32 api_client_index)
{
  uri_main_t * um = &uri_main;
  api_main_t *am = &api_main;
  stream_server_main_t * ssm = &stream_server_main;
  stream_server_t * ss;
  vl_api_registration_t *regp;
  uword * p;
  void * oldheap;
  char * cp;
  u32 port_number_host_byte_order;
  u16 * n;
  int i, j;

  p = hash_get_mem (um->fifo_bind_table_entry_by_name, uri);

  if (!p)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  /* External client? */
  if (api_client_index != ~0)
    {
      regp = vl_api_client_index_to_registration (api_client_index);
      ASSERT(regp);
    }

  /* "udp4:12345" */
  cp = (char *) &uri[5];
  if (*cp == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  port_number_host_byte_order = 0;
  while (*cp != 0 && (*cp >= '0' && *cp <= '9'))
    {
      port_number_host_byte_order = (port_number_host_byte_order<<3) + 
        (port_number_host_byte_order<<1);
      port_number_host_byte_order += *cp - '0';
      cp++;
    }

  if (port_number_host_byte_order > 65535)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Turn off the uri-queue mapping */
  n = sparse_vec_validate (ssm->stream_server_by_dst_port, 
                           clib_host_to_net_u16(port_number_host_byte_order));
  n[0] = SPARSE_VEC_INVALID_INDEX;

  /* deregister the udp_local mapping */
  udp_unregister_dst_port (um->vlib_main, port_number_host_byte_order, 
                           1 /* is_ipv4 */);

  /* 
   * Find the stream_server_t corresponding to the api client 
   * $$$$ maybe add a hash table? There may only be three or four... 
   */
  pool_foreach (ss, ssm->servers, 
  ({ 
    if (ss->api_client_index == api_client_index)
      goto found;
  }));

  /* Better never happen... */
  return VNET_API_ERROR_INVALID_VALUE_2;

 found:

  /* Across all fifo segment used by the server */
  for (j = 0; j < vec_len (ss->segment_indices); j++)
    {
      svm_fifo_segment_private_t * fifo_segment;
      svm_fifo_t ** fifos;
      /* Vector of fifos allocated in the segment */
      fifo_segment = svm_fifo_get_segment (ss->segment_indices[j]);
      fifos = (svm_fifo_t **) fifo_segment->h->fifos;

      /* 
       * Remove any residual sessions from the session lookup table 
       * Don't bother deleting the individual fifos, we're going to 
       * throw away the fifo segment in a minute.
       */
      for (i = 0; i < vec_len(fifos); i++)
        {
          clib_bihash_kv_16_8_t kv0;
          svm_fifo_t * fifo;
          u32 session_index, thread_index;
          stream_session_t * session;
          
          fifo = fifos[0];
          session_index = fifo->server_session_index;
          thread_index = fifo->server_thread_index;
          
          session = pool_elt_at_index (ssm->sessions[thread_index], 
                                       session_index);
          
          kv0.key[0] = session->u4.key.as_u64[0];
          kv0.key[1] = session->u4.key.as_u64[1];
          kv0.value = ~0ULL;
          
          clib_bihash_add_del_16_8 (&ssm->v4_session_hash, &kv0, 
                                    0 /* is_add */);
        }

      svm_fifo_segment_delete (fifo_segment);
    }

  /* Free the event fifo in the /vpe-api shared-memory segment */
  oldheap = svm_push_data_heap (am->vlib_rp);

  if (ss->event_queue)
    unix_shared_memory_queue_free (ss->event_queue);

  svm_pop_heap (oldheap);

  /* Clean out the uri->server name mapping */
  hash_unset_mem (um->fifo_bind_table_entry_by_name, uri);
  pool_put_index (um->fifo_bind_table, p[0]);

  pool_put (ssm->servers, ss);

  return 0;
}

int vnet_disconnect_udp4_uri (char * uri, u32 api_client_index)
{
  clib_warning ("STUB");
  return (-1);
}

u32 uri_tx_ip4_udp (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  svm_fifo_t * f;
  ip4_header_t * ip;
  udp_header_t * udp;
  u8 * data;
  u32 max_dequeue, len_to_dequeue, actual_length;
  udp4_session_t *us;

  us = &s->u4;
  f = s->server_tx_fifo;
  ip = vlib_buffer_get_current (b);
  udp = (udp_header_t *)(ip+1);
  data = (u8 *)(udp+1);

  /* Dequeue a bunch of data into the packet buffer */
  max_dequeue = svm_fifo_max_dequeue (f);

  if (max_dequeue == 0)
    {
      /* $$$$ set b0->error = node->errors[nil dequeue] */
      return URI_QUEUE_NEXT_DROP;
    }

  len_to_dequeue = max_dequeue < s->u4.mtu ? max_dequeue : s->u4.mtu;
  
  actual_length = svm_fifo_dequeue (f, 0, len_to_dequeue, data);

  b->current_length = sizeof (*ip) + sizeof (*udp) + actual_length;

  /* Build packet header, swap rx key src + dst fields */
  ip->src_address.as_u32 = us->key.as_key.dst.as_u32;
  ip->dst_address.as_u32 = us->key.as_key.src.as_u32;
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->length = clib_host_to_net_u16 (b->current_length);
  ip->checksum = ip4_header_checksum(ip);

  udp->src_port = us->key.as_key.dst_port;
  udp->dst_port = us->key.as_key.src_port;
  udp->length = clib_host_to_net_u16 (actual_length + sizeof (*udp));
  udp->checksum = 0;
  
  return URI_QUEUE_NEXT_IP4_LOOKUP;
}


u32 uri_tx_ip4_tcp (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  clib_warning ("unimplmented");
  return 0;
}
u32 uri_tx_ip6_tcp (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  clib_warning ("unimplmented");
  return 0;
}
u32 uri_tx_ip6_udp (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  clib_warning ("unimplmented");
  return 0;
}
u32 uri_tx_fifo (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  clib_warning ("unimplmented");
  return 0;
}

static clib_error_t *
show_uri_server_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  uri_main_t *um = &uri_main;
  fifo_bind_table_entry_t * e;
  int verbose = 0;
  
  if (unformat (input, "verbose"))
    verbose = 1;

  if (pool_elts (um->fifo_bind_table))
    {
      vlib_cli_output (vm, "%U", format_bind_table_entry, 0 /* header */,
                       verbose);
      pool_foreach (e, um->fifo_bind_table,
      ({
        vlib_cli_output (vm, "%U", format_bind_table_entry, e, verbose);
      }));
    }
  else
    vlib_cli_output (vm, "No active server bindings");

  return 0;
}

VLIB_CLI_COMMAND (show_uri_server_command, static) = {
    .path = "show uri server",
    .short_help = "show uri server",
    .function = show_uri_server_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
