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
#include <vnet/uri/uri.h>
#include <vnet/session/session.h>
#include <vlibmemory/api.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>

/** @file
    URI handling, bind tables
*/

uri_main_t uri_main;

/**
 * unformat a vnet URI
 *
 * fifo://name
 * tcp://ip46-addr:port
 * udp://ip46-addr:port
 *
 * u8 ip46_address[16];
 * u16  port_in_host_byte_order;
 * stream_session_type_t sst;
 * u8 *fifo_name;
 *
 * if (unformat (input, "%U", unformat_vnet_uri, &ip46_address,
 *              &sst, &port, &fifo_name))
 *  etc...
 *
 */
uword
unformat_vnet_uri (unformat_input_t * input, va_list * args)
{
  ip46_address_t * address = va_arg (*args, ip46_address_t *);
  session_type_t * sst = va_arg (*args, session_type_t *);
  u16 * port = va_arg(*args, u16 *);

  if (unformat (input, "tcp://%U/%d", unformat_ip4_address, &address->ip4,
                port))
    {
      *sst = SESSION_TYPE_IP4_TCP;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip4_address, &address->ip4,
                port))
    {
      *sst = SESSION_TYPE_IP4_UDP;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip6_address, &address->ip6,
                port))
    {
      *sst = SESSION_TYPE_IP6_UDP;
      return 1;
    }
  if (unformat (input, "tcp://%U/%d", unformat_ip6_address, &address->ip6,
                port))
    {
      *sst = SESSION_TYPE_IP6_TCP;
      return 1;
    }

  return 0;
}

int
parse_uri (char *uri, session_type_t *sst, ip46_address_t *addr,
           u16 *port_number_host_byte_order)
{
  unformat_input_t _input, *input = &_input;

  /* Make sure */
  uri = (char *)format (0, "%s%c", uri, 0);

  /* Parse uri */
  unformat_init_string (input, uri, strlen (uri));
  if (!unformat (input, "%U", unformat_vnet_uri, addr, sst,
                 port_number_host_byte_order))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  unformat_free (input);

  return 0;
}

static u8
ip_is_zero (ip46_address_t *ip46_address, u8 is_ip4)
{
  if (is_ip4)
    return (ip46_address->ip4.as_u32 == 0);
  else
    return (ip46_address->as_u64[0] == 0 && ip46_address->as_u64[1] == 0);
}

static u8
ip_is_local (ip46_address_t *ip46_address, u8 is_ip4)
{
  fib_node_index_t fei;
  fib_entry_flag_t flags;
  fib_prefix_t prefix;

  /* Check if requester is local */
  if (is_ip4)
    {
      prefix.fp_len = 32;
      prefix.fp_proto = FIB_PROTOCOL_IP4;
    }
  else
    {
      prefix.fp_len = 128;
      prefix.fp_proto = FIB_PROTOCOL_IP6;
    }

  clib_memcpy(&prefix.fp_addr, ip46_address, sizeof(ip46_address));
  fei = fib_table_lookup (0, &prefix);
  flags = fib_entry_get_flags (fei);

  return (flags & FIB_ENTRY_FLAG_LOCAL);
}

int
vnet_bind_uri (vnet_bind_uri_args_t *a)
{
  u8 * segment_name = 0;
  application_t *server = 0;
  u16 port_host_order;
  session_type_t sst = SESSION_N_TYPES;
  ip46_address_t ip46;
  u8 is_ip4;
  stream_session_t *listener;
  int rv;

  rv = parse_uri (a->uri, &sst, &ip46, &port_host_order);
  if (rv)
    return rv;

  listener = stream_session_lookup_listener (
      &ip46, clib_host_to_net_u16 (port_host_order), sst);

  if (listener)
    return VNET_API_ERROR_ADDRESS_IN_USE;

  if (application_lookup (a->api_client_index))
    {
      clib_warning ("Only one bind supported for now");
      return VNET_API_ERROR_ADDRESS_IN_USE;
    }

  /*
   * $$$$ lookup client by api client index, to see if we're already
   * talking to this client about some other port
   */

  is_ip4 = SESSION_TYPE_IP4_UDP == sst || SESSION_TYPE_IP4_TCP == sst;
  if (!ip_is_zero (&ip46, is_ip4) && !ip_is_local (&ip46, is_ip4))
    return VNET_API_ERROR_INVALID_VALUE;

  /* Allocate and initialize stream server */
  server = application_new (APP_SERVER, sst, a->api_client_index,
                            a->options[URI_OPTIONS_FLAGS], a->session_cb_vft);

  application_server_init (server, a->segment_size,
                           a->options[URI_OPTIONS_ADD_SEGMENT_SIZE],
                           a->options[URI_OPTIONS_RX_FIFO_SIZE],
                           a->options[URI_OPTIONS_TX_FIFO_SIZE],
                           &segment_name);

  /* Setup listen path down to transport */
  stream_session_start_listen (server->index, &ip46, port_host_order);

  /*
   * Return values
   */

  ASSERT (vec_len(segment_name) <= 128);
  a->segment_name_length = vec_len(segment_name);
  memcpy (a->segment_name, segment_name, a->segment_name_length);
  a->server_event_queue_address = (u64) server->event_queue;

  return 0;
}

int
vnet_unbind_uri (char *uri, u32 api_client_index)
{
  application_t * server;
  vl_api_registration_t *regp;
  u16 port_number_host_byte_order;
  session_type_t sst = SESSION_N_TYPES;
  ip46_address_t ip46_address;
  stream_session_t *listener;
  int rv;

  rv = parse_uri (uri, &sst, &ip46_address, &port_number_host_byte_order);
  if (rv)
    return rv;

  listener = stream_session_lookup_listener (
       &ip46_address, clib_host_to_net_u16 (port_number_host_byte_order), sst);

  if (!listener)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  /* External client? */
  if (api_client_index != ~0)
    {
      regp = vl_api_client_index_to_registration (api_client_index);
      ASSERT(regp);
    }

  /*
   * Find the stream_server_t corresponding to the api client
   */
  server = application_lookup (api_client_index);
  if (!server)
    return VNET_API_ERROR_INVALID_VALUE_2;

  /* Clear the listener */
  stream_session_stop_listen (server->index);
  application_del (server);

  return 0;
}

int
redirect_connect_uri_callback (u32 api_client_index, void *mp) __attribute__((weak));

int redirect_connect_uri_callback (u32 api_client_index, void *mp)
{
  clib_warning ("STUB");
  return -1;
}

int
vnet_connect_uri (vnet_connect_uri_args_t *a)
{
  ip46_address_t ip46_address;
  u16 port;
  session_type_t sst;
  stream_session_t *listener;
  application_t *server, *app;
  int rv;

  app = application_lookup (a->api_client_index);
  if (app)
    {
      clib_warning ("Already have a connect from this app");
      return VNET_API_ERROR_INVALID_VALUE_2;
    }

  /* Parse uri */
  rv = parse_uri (a->uri, &sst, &ip46_address, &port);
  if (rv)
    return rv;

  /* Create client app */
  app = application_new (APP_CLIENT, sst, a->api_client_index,
                         a->options[URI_OPTIONS_FLAGS], a->session_cb_vft);

  /*
   * Figure out if connecting to a local server
   */
  listener = stream_session_lookup_listener (&ip46_address,
                                             clib_host_to_net_u16 (port),
                                             sst);
  if (listener)
    {
      server = application_get (listener->app_index);

      /*
       * Server is willing to have a direct fifo connection created
       * instead of going through the state machine, etc.
       */
      if (server->flags & URI_OPTIONS_FLAGS_USE_FIFO)
        return server->cb_fns.redirect_connect_callback (
            server->api_client_index, a->mp);
    }

  /*
   * Not connecting to a local server. Create regular session
   */
  stream_session_open (sst, &ip46_address, port, app->index);

  return 0;
}

int
vnet_disconnect_uri (u32 client_index, u32 session_index, u32 thread_index)
{
  stream_session_t *session;

  session = stream_session_get (session_index, thread_index);
  stream_session_delete (session);

  return 0;
}

int
uri_api_session_not_valid (u32 session_index, u32 thread_index)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  stream_session_t *pool;

  if (thread_index >= vec_len (smm->sessions))
    return VNET_API_ERROR_INVALID_VALUE;

  pool = smm->sessions[thread_index];

  if (pool_is_free_index (pool, session_index))
    return VNET_API_ERROR_INVALID_VALUE_2;

  return 0;
}

static clib_error_t *
uri_init (vlib_main_t * vm)
{
  uri_main_t * um = &uri_main;

  um->vlib_main = vm;
  um->vnet_main = vnet_get_main();
  return 0;
}

VLIB_INIT_FUNCTION (uri_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
