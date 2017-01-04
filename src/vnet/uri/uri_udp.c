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

#include <vnet/uri/uri.h>
#include <vnet/ip/udp.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>

/* Per-worker thread udp connection pools */
udp_session_t **udp_sessions;
udp_session_t *udp_listeners;

u32
vnet_bind_ip4_udp_uri (vlib_main_t *vm, u32 session_index, ip46_address_t *ip,
                       u16 port_number_host_byte_order)
{
  udp_session_t *listener;
  pool_get(udp_listeners, listener);
  memset (listener, 0, sizeof (udp_session_t));
  listener->c_lcl_port = clib_host_to_net_u16 (port_number_host_byte_order);
  listener->c_lcl_ip4.as_u32 = ip->ip4.as_u32;
  listener->c_proto = SESSION_TYPE_IP4_UDP;
  udp_register_dst_port (vm, port_number_host_byte_order,
                         udp4_uri_input_node.index, 1 /* is_ipv4 */);
  return 0;
}

u32
vnet_bind_ip6_udp_uri (vlib_main_t *vm, u32 session_index, ip46_address_t *ip,
                       u16 port_number_host_byte_order)
{
  udp_session_t *listener;
  pool_get(udp_listeners, listener);
  listener->c_lcl_port = clib_host_to_net_u16 (port_number_host_byte_order);
  clib_memcpy (&listener->c_lcl_ip6, &ip->ip6, sizeof(ip6_address_t));
  listener->c_proto = SESSION_TYPE_IP6_UDP;
  udp_register_dst_port (vm, port_number_host_byte_order,
                         udp4_uri_input_node.index, 0 /* is_ipv4 */);
  return 0;
}

u32
vnet_unbind_ip4_udp_uri (vlib_main_t *vm, u32 listener_index)
{
  udp_session_t *listener = pool_elt_at_index(udp_listeners, listener_index);
  /* deregister the udp_local mapping */
  udp_unregister_dst_port (vm, listener->c_lcl_port, 1 /* is_ipv4 */);
  return 0;
}

u32
vnet_unbind_ip6_udp_uri (vlib_main_t *vm, u32 listener_index)
{
  udp_session_t *listener = pool_elt_at_index(udp_listeners, listener_index);
  /* deregister the udp_local mapping */
  udp_unregister_dst_port (vm, listener->c_lcl_port, 0 /* is_ipv4 */);
  return 0;
}

transport_connection_t *
uri_udp_session_get_listener (u32 listener_index)
{
  udp_session_t *us;
  us = pool_elt_at_index (udp_listeners, listener_index);
  return &us->connection;
}

//int
//vnet_connect_ip4_udp (ip4_address_t *ip_address, u16 port,
//                      u32 api_client_index, u64 * options,
//                      u8 * segment_name, u32 * name_length, void *mp)
//{
//  stream_server_main_t *ssm = &stream_server_main;
//  stream_server_t *ss;
//  ip4_fib_t * fib;
//  u32 fib_index;
//  ip4_fib_mtrie_leaf_t leaf0;
//  ip4_address_t * dst_addr0;
//  u32 lbi0;
//  const load_balance_t * lb0;
//  const dpo_id_t *dpo0;
//  ip4_fib_mtrie_t * mtrie0;
//  stream_session_t *s;
//
//  /*
//   * Connect to a local URI?
//   */
//  s = stream_session_lookup_listener4 (ip_address, port,
//                                       SESSION_TYPE_IP4_UDP);
//
//  /* Find the server */
//  if (s)
//    ss = pool_elt_at_index(ssm->servers, s->server_index);
//
//  /*
//   * Server is willing to have a direct fifo connection created
//   * instead of going through the state machine, etc.
//   */
//
//  if (!s || (ss->flags & URI_OPTIONS_FLAGS_USE_FIFO) == 0)
//    goto create_regular_session;
//
//  /* Look up <address>, and see if we hit a local adjacency */
//
//  /* $$$$$ move this to a fib fcn. */
//  /* Default FIB ($$$for the moment) */
//  fib_index = ip4_fib_index_from_table_id (0);
//  ASSERT (fib_index != ~0);
//  fib = ip4_fib_get (fib_index);
//
//  dst_addr0 = ip_address;
//  mtrie0 = &fib->mtrie;
//  leaf0 = IP4_FIB_MTRIE_LEAF_ROOT;
//  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 0);
//  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 1);
//  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 2);
//  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 3);
//  if (leaf0 == IP4_FIB_MTRIE_LEAF_EMPTY)
//    goto create_regular_session;
//
//  lbi0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
//  lb0 = load_balance_get (lbi0);
//
//  /* Local (interface) adjs are not load-balanced... */
//  if (lb0->lb_n_buckets > 1)
//    goto create_regular_session;
//  dpo0 = load_balance_get_bucket_i (lb0, 0);
//  /* $$$$$ end move this to a fib fcn. */
//
//  if (dpo0->dpoi_type == DPO_RECEIVE)
//    {
//      int rv;
//      /* redirect to the server */
//      rv = redirect_connect_uri_callback (ss->api_client_index, mp);
//      return rv;
//    }
//
// create_regular_session:
//  return VNET_API_ERROR_UNIMPLEMENTED;
//}

u32
uri_tx_ip4_udp (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  svm_fifo_t * f;
  ip4_header_t * ip;
  udp_header_t * udp;
  u8 * data;
  u32 max_dequeue, len_to_dequeue, actual_length;
  udp_session_t *us;
  u32 my_thread_index = vm->cpu_index;

  ASSERT(s->session_thread_index == my_thread_index);

  us = pool_elt_at_index(udp_sessions[my_thread_index],
                         s->connection_index);

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

  len_to_dequeue = max_dequeue < us->mtu ? max_dequeue : us->mtu;

  actual_length = svm_fifo_dequeue (f, 0, len_to_dequeue, data);

  b->current_length = sizeof (*ip) + sizeof (*udp) + actual_length;

  /* Build packet header, swap rx key src + dst fields */
  ip->src_address.as_u32 = us->c_lcl_ip4.as_u32;
  ip->dst_address.as_u32 = us->c_rmt_ip4.as_u32;
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->length = clib_host_to_net_u16 (b->current_length);
  ip->checksum = ip4_header_checksum(ip);

  udp->src_port = us->c_lcl_port;
  udp->dst_port = us->c_rmt_port;
  udp->length = clib_host_to_net_u16 (actual_length + sizeof (*udp));
  udp->checksum = 0;

  return URI_QUEUE_NEXT_IP4_LOOKUP;
}

transport_connection_t *
uri_udp_session_get (u32 connection_index, u32 my_thread_index)
{
  udp_session_t * us;
  us = pool_elt_at_index (udp_sessions[my_thread_index], connection_index);
  return &us->connection;
}

void
uri_udp_session_delete (u32 connection_index, u32 my_thread_index)
{
  pool_put_index (udp_sessions[my_thread_index], connection_index);
}

u8 *
format_ip4_udp_stream_session (u8 * s, va_list * args)
{
  u32 tsi = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  udp_session_t *u4;

  u4 = pool_elt_at_index(udp_sessions[thread_index], tsi);

  s = format (s, "%-20U%-20U%-10d%-10d%-8s", format_ip4_address,
              &u4->c_lcl_ip4, format_ip4_address, &u4->c_rmt_ip4,
              clib_net_to_host_u16 (u4->c_lcl_port),
              clib_net_to_host_u16 (u4->c_rmt_port), "udp");

  return s;
}

u8*
format_stream_session_ip6_udp (u8 *s, va_list *args)
{
  clib_warning ("unimplmented");
  return 0;
}

u8*
format_stream_session_fifo (u8 *s, va_list *args)
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

const static transport_proto_vft_t udp4_proto = {
  .bind = vnet_bind_ip4_udp_uri,
  .unbind = vnet_unbind_ip4_udp_uri,
  .send = uri_tx_ip4_udp,
  .get_connection = uri_udp_session_get,
  .get_listener = uri_udp_session_get_listener,
  .delete_connection = uri_udp_session_delete,
  .format_connection = format_ip4_udp_stream_session
};

static clib_error_t *
uri_udp4_module_init (vlib_main_t * vm)
{
  u32 num_threads;
  vlib_thread_main_t *tm = &vlib_thread_main;

  num_threads = 1 /* main thread */ + tm->n_eal_threads;

  uri_register_transport (SESSION_TYPE_IP4_UDP, &udp4_proto);

  /** FIXME move to udp main */
  vec_validate (udp_sessions, num_threads - 1);
  return 0;
}

VLIB_INIT_FUNCTION (uri_udp4_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
