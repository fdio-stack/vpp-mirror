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

u32
vnet_bind_ip4_udp_uri (uri_main_t * um, u16 port_number_host_byte_order)
{
  udp_register_dst_port (um->vlib_main, port_number_host_byte_order,
                         udp4_uri_input_node.index, 1 /* is_ipv4 */);
  return 0;
}

u32
vnet_bind_ip6_udp_uri (uri_main_t * um, u16 port_number_host_byte_order)
{
  udp_register_dst_port (um->vlib_main, port_number_host_byte_order,
                         udp4_uri_input_node.index, 0 /* is_ipv4 */);
  return 0;
}


u32
vnet_unbind_ip4_udp_uri (uri_main_t * um, u16 port_number_host_byte_order)
{
  /* deregister the udp_local mapping */
  udp_unregister_dst_port (um->vlib_main, port_number_host_byte_order,
                           1 /* is_ipv4 */);

  return 0;
}

u32
vnet_unbind_ip6_udp_uri (uri_main_t * um, u16 port_number_host_byte_order)
{
  /* deregister the udp_local mapping */
  udp_unregister_dst_port (um->vlib_main, port_number_host_byte_order,
                           0 /* is_ipv4 */);

  return 0;
}

u32 uri_tx_ip4_udp (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  svm_fifo_t * f;
  ip4_header_t * ip;
  udp_header_t * udp;
  u8 * data;
  u32 max_dequeue, len_to_dequeue, actual_length;
  udp4_session_t *us;
  u32 my_thread_index = vm->cpu_index;

  ASSERT(s->session_thread_index == my_thread_index);

  us = pool_elt_at_index(udp4_sessions[my_thread_index],
                         s->transport_connection_index);
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

u8 * format_stream_session_ip4_udp (u8 * s, va_list * args)
{
  u32 * si = va_arg (*args, u32 *);
  u32 * ti = va_arg (*args, u32 *);
  udp4_session_t *u4;

  u4 = pool_elt_at_index (udp4_sessions[ti[0]], si[0]);
  
  s = format (s, "%-20U%-20U%-10d%-10d%-8s", format_ip4_address,
              &u4->key.as_key.src, format_ip4_address, &u4->key.as_key.dst,
              clib_net_to_host_u16 (u4->key.as_key.src_port),
              clib_net_to_host_u16 (u4->key.as_key.dst_port), "udp");

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
