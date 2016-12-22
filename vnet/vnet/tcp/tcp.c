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

#include <vnet/tcp/tcp.h>
#include <vnet/uri/uri_db.h>
#include <math.h>

tcp_main_t tcp_main;

static u32
tcp_uri_bind (vlib_main_t *vm, u32 session_index, ip46_address_t *ip,
              u16 port_host_byte_order, u8 is_ip4)
{
  tcp_main_t * tm = vnet_get_tcp_main ();
  tcp_connection_t * l;

  pool_get(tm->listener_pool, l);
  memset(l, 0, sizeof(*l));

  l->s_t_index = l - tm->listener_pool;
  l->s_lcl_port = clib_host_to_net_u16 (port_host_byte_order);

  if (is_ip4)
    l->s_lcl_ip4.as_u32 = ip->ip4.as_u32;
  else
    clib_memcpy (&l->s_lcl_ip6, &ip->ip6, sizeof(ip6_address_t));

  l->s_s_index = session_index;
  l->s_proto = SESSION_TYPE_IP4_TCP;
  l->state = TCP_CONNECTION_STATE_LISTEN;
  l->is_ip4 = 1;

  return l->s_t_index;
}

u32
tcp_uri_bind_ip4 (vlib_main_t * vm, u32 session_index, ip46_address_t *ip,
                  u16 port_host_byte_order)
{
  return tcp_uri_bind (vm, session_index, ip, port_host_byte_order, 1);
}

u32
tcp_uri_bind_ip6 (vlib_main_t * vm, u32 session_index, ip46_address_t *ip,
                  u16 port_host_byte_order)
{
  return tcp_uri_bind (vm, session_index, ip, port_host_byte_order, 0);

}

static void
tcp_uri_unbind (u32 listener_index)
{
  tcp_main_t * tm = vnet_get_tcp_main ();
  pool_put_index (tm->listener_pool, listener_index);
}

u32
tcp_uri_unbind_ip4 (vlib_main_t * vm, u32 listener_index)
{
  tcp_uri_unbind (listener_index);
  return 0;
}

u32
tcp_uri_unbind_ip6 (vlib_main_t * vm, u32 listener_index)
{
  tcp_uri_unbind (listener_index);
  return 0;
}

transport_session_t *
tcp_uri_session_get_listener (u32 listener_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;
  tc = pool_elt_at_index (tm->listener_pool, listener_index);
  return &tc->session;
}

u8*
format_tcp_stream_session_ip4 (u8 *s, va_list *args)
{
  u32 tci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  tcp_connection_t *tc;

  tc = tcp_connection_get (tci, thread_index);

  s = format (s, "%-20U%-20U%-10d%-10d%-8s", format_ip4_address,
              &tc->s_lcl_ip4, format_ip4_address, &tc->s_rmt_ip4,
              clib_net_to_host_u16 (tc->s_lcl_port),
              clib_net_to_host_u16 (tc->s_rmt_port), "tcp");

  return s;
}

u8*
format_tcp_stream_session_ip6 (u8 *s, va_list *args)
{
  u32 tci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  tcp_connection_t *tc;

  tc = tcp_connection_get (tci, thread_index);

  s = format (s, "%-20U%-20U%-10d%-10d%-8s", format_ip6_address,
              &tc->s_lcl_ip6, format_ip6_address, &tc->s_rmt_ip6,
              clib_net_to_host_u16 (tc->s_lcl_port),
              clib_net_to_host_u16 (tc->s_rmt_port), "tcp");

  return s;
}

void
tcp_uri_session_delete (u32 transport_session_index, u32 my_thread_index)
{
  tcp_connection_delete (transport_session_index, my_thread_index);
}

transport_session_t *
tcp_uri_session_get (u32 tc_index, u32 my_thread_index)
{
  tcp_connection_t *tc = tcp_connection_get (tc_index, my_thread_index);
  return &tc->session;
}

const static transport_proto_vft_t tcp4_proto = {
  .bind = tcp_uri_bind_ip4,
  .unbind = tcp_uri_unbind_ip4,
  .send = tcp_uri_tx_packetize_ip4,
  .get_session = tcp_uri_session_get,
  .get_listener = tcp_uri_session_get_listener,
  .delete_session = tcp_uri_session_delete,
  .format_session = format_tcp_stream_session_ip4
};

const static transport_proto_vft_t tcp6_proto = {
  .bind = tcp_uri_bind_ip6,
  .unbind = tcp_uri_unbind_ip6,
  .send = tcp_uri_tx_packetize_ip6,
  .get_session = tcp_uri_session_get,
  .get_listener = tcp_uri_session_get_listener,
  .delete_session = tcp_uri_session_delete,
  .format_session = format_tcp_stream_session_ip6
};

static timer_expiration_handler timer_expiration_handlers[TCP_N_TIMERS] =
  { 0, timer_delack_handler, 0, 0, 0 };

static void
tcp_expired_timers_dispatch (u32 *expired_timers)
{
  int i;
  u32 connection_index, timer_id;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session index and timer id */
      connection_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      /* Handle expiration */
      (*timer_expiration_handlers[timer_id]) (connection_index);
    }
}

clib_error_t *
tcp_init (vlib_main_t * vm)
{
  ip_main_t * im = &ip_main;
  ip_protocol_info_t * pi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_thread_main_t *vtm = &vlib_thread_main;
  clib_error_t * error = 0;
  f64 log2 = .69314718055994530941;
  u32 num_threads;

  tm->vlib_main = vm;
  tm->vnet_main = vnet_get_main ();

  if ((error = vlib_call_init_function(vm, ip_main_init)))
    return error;
  if ((error = vlib_call_init_function(vm, ip4_lookup_init)))
    return error;
  if ((error = vlib_call_init_function(vm, ip6_lookup_init)))
    return error;

  /*
   * Registrations
   */

  /* Register with IP */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_TCP);
  if (pi == 0)
      return clib_error_return (0, "TCP protocol info AWOL");
  pi->format_header = format_tcp_header;
  pi->unformat_pg_edit = unformat_pg_tcp_header;

  ip4_register_protocol (IP_PROTOCOL_TCP, tcp4_input_node.index);

  /* Register as transport with URI */
  uri_register_transport (SESSION_TYPE_IP4_TCP, &tcp4_proto);
  uri_register_transport (SESSION_TYPE_IP6_TCP, &tcp6_proto);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */ + vtm->n_eal_threads;
  vec_validate (tm->connections, num_threads - 1);

  /* Initialize per worker thread tx buffers (used for control messages) */
  vec_validate (tm->tx_buffers, num_threads - 1);

  /* Initialize timer wheel */
  tcp_timer_wheel_init (&tm->timer_wheel, tcp_expired_timers_dispatch);
  tm->timer_wheel.last_run_time = vlib_time_now (vm);

  /* Initialize clocks per tick for TCP timestamp. Used to compute
   * monotonically increasing timestamps. */
  tm->log2_tstamp_clocks_per_tick = flt_round_nearest (
      log (TCP_TSTAMP_RESOLUTION / vm->clib_time.seconds_per_clock) / log2);

  return error;
}

VLIB_INIT_FUNCTION (tcp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
