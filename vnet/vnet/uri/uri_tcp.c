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
    tcp uri
*/

#include <vnet/uri/uri.h>
#include <vnet/tcp/tcp.h>

u32
vnet_bind_ip4_tcp_uri (vlib_main_t * vm, u16 port_number_host_byte_order)
{
  tcp_listener_registration_t _a, *a = &_a;

  a->port = port_number_host_byte_order;
  a->event_function = 0;
  a->flags = TCP_LISTENER_IP4;
  a->data_node_index = tcp4_uri_input_node.index;

  tcp_register_listener (vm, a);

  return 0;
}

u32
vnet_bind_ip6_tcp_uri (vlib_main_t * vm, u16 port_number_host_byte_order)
{
  tcp_listener_registration_t _a, *a = &_a;

  a->port = port_number_host_byte_order;
  a->event_function = 0;
  a->flags = TCP_LISTENER_IP6;
  a->data_node_index = tcp6_uri_input_node.index;

  tcp_register_listener (vm, a);

  return 0;
}

u32
vnet_unbind_ip4_tcp_uri (vlib_main_t * vm, u16 port)
{
  clib_warning ("unimplmented");
  return 0;
}

u32
vnet_unbind_ip6_tcp_uri (vlib_main_t * vm, u16 port)
{
  clib_warning ("unimplmented");
  return 0;
}

u8*
format_stream_session_ip4_tcp (u8 *s, va_list *args)
{
  clib_warning ("unimplmented");
  return 0;
}

u8*
format_stream_session_ip6_tcp (u8 *s, va_list *args)
{
  clib_warning ("unimplmented");
  return 0;
}

u32 uri_tx_ip4_tcp (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  svm_fifo_t * f;
  ip4_header_t * ip;
  tcp_header_t * tcp;
  u8 * data;
  u32 max_dequeue, len_to_dequeue, actual_length;
  tcp_session_t *us;
  u32 my_thread_index = vm->cpu_index;

  ASSERT(s->session_thread_index == my_thread_index);

  /** FIXME compute based on offset */
  us = (tcp_session_t *) s->transport;

  f = s->server_tx_fifo;
  ip = vlib_buffer_get_current (b);
  tcp = (tcp_header_t *)(ip+1);
  data = (u8 *)(tcp+1);

  /* Dequeue a bunch of data into the packet buffer */
  max_dequeue = svm_fifo_max_dequeue (f);

  if (max_dequeue == 0)
    {
      /* $$$$ set b0->error = node->errors[nil dequeue] */
      return URI_QUEUE_NEXT_DROP;
    }

//  len_to_dequeue = max_dequeue < us->mtu ? max_dequeue : us->mtu;
  len_to_dequeue = 0;
  actual_length = svm_fifo_dequeue (f, 0, len_to_dequeue, data);

  b->current_length = sizeof (*ip) + sizeof (*tcp) + actual_length;

  /* Build packet header, swap rx key src + dst fields */
  ip->src_address.as_u32 = us->s_lcl_ip4.as_u32;
  ip->dst_address.as_u32 = us->s_rmt_ip4.as_u32;
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_TCP;
  ip->length = clib_host_to_net_u16 (b->current_length);
  ip->checksum = ip4_header_checksum(ip);

  tcp->src = us->s_lcl_port;
  tcp->dst = us->s_rmt_port;
//  tcp->length = clib_host_to_net_u16 (actual_length + sizeof (*tcp));
//  tcp->checksum = 0;

  /** FIXME send to TCP output ??*/
  return URI_QUEUE_NEXT_IP4_LOOKUP;
}

u32
uri_tx_ip6_tcp (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  clib_warning ("unimplmented");
  return 0;
}

const static transport_proto_vft_t tcp4_proto = {
  .bind = vnet_bind_ip4_tcp_uri,
  .unbind = vnet_unbind_ip4_tcp_uri,
  .send = uri_tx_ip4_tcp,
  .format_session = format_stream_session_ip4_tcp
};

static clib_error_t *
uri_tcp4_module_init (vlib_main_t * vm)
{
  uri_register_transport (SESSION_TYPE_IP4_TCP, &tcp4_proto);
  return 0;
}

VLIB_INIT_FUNCTION (uri_tcp4_module_init);

const static transport_proto_vft_t tcp6_proto = {
  .bind = vnet_bind_ip6_tcp_uri,
  .unbind = vnet_unbind_ip6_tcp_uri,
  .send = uri_tx_ip6_tcp,
  .format_session = format_stream_session_ip6_tcp
};

static clib_error_t *
uri_tcp6_module_init (vlib_main_t * vm)
{
  uri_register_transport (SESSION_TYPE_IP6_TCP, &tcp6_proto);
  return 0;
}

VLIB_INIT_FUNCTION (uri_tcp6_module_init);
