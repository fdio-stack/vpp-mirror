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

/**** fifo uri */

u32
vnet_bind_fifo_uri (uri_main_t *um, u16 port)
{
  return 0;
}

u32
vnet_unbind_fifo_uri (uri_main_t *um, u16 port)
{
  return 0;
}

int
vnet_connect_fifo_uri (char *uri, u32 api_client_index, u64 * options,
                       char *segment_name_arg, u32 * segment_name_length)
{
  uri_main_t * um = &uri_main;
  uri_bind_table_entry_t * e;
  uword * p;

  ASSERT(segment_name_length);

  p = hash_get_mem (um->uri_bind_table_entry_by_name, uri);

  if (!p)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  e = pool_elt_at_index (um->fifo_bind_table, p[0]);

  *segment_name_length = vec_len(e->segment_name);
  memcpy (segment_name_arg, e->segment_name, *segment_name_length);
  e->connect_client_index = api_client_index;

  return 0;
}

/**** end fifo URI */

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
  stream_session_type_t * sst = va_arg (*args, stream_session_type_t *);
  u16 * port = va_arg(*args, u16 *);
  u8 ** fifo_name = va_arg(*args, u8 **);
  u8 * name = 0;

  *fifo_name = 0;

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
  if (unformat (input, "fifo://%s", name))
    {
      *fifo_name = name;
      *sst = SESSION_TYPE_FIFO;
      return 1;
    }

  return 0;
}
uri_bind_table_entry_t *
fifo_bind_table_lookup (uri_main_t *um, char *uri)
{
  uword *p;
  p = hash_get_mem (um->uri_bind_table_entry_by_name, uri);
  if (!p)
     return 0;

  return pool_elt_at_index (um->fifo_bind_table, p[0]);
}

void
fifo_bind_table_add (uri_main_t *um, u8 *uri, u8 *server_name,
                    u8 *segment_name, u32 api_client_index, u32 accept_cookie)
{
  uri_bind_table_entry_t * e;

  pool_get(um->fifo_bind_table, e);
  memset(e, 0, sizeof(*e));

  e->bind_name = uri;
  e->server_name = server_name;
  e->segment_name = segment_name;
  e->bind_client_index = api_client_index;
  e->accept_cookie = accept_cookie;

  hash_set_mem(um->uri_bind_table_entry_by_name, e->bind_name,
               e - um->fifo_bind_table);
}

int
fifo_bind_table_del (uri_main_t *um, uri_bind_table_entry_t *e)
{

  hash_unset_mem(um->uri_bind_table_entry_by_name, e->bind_name);
  pool_put(um->fifo_bind_table, e);

  return 0;
}

int
vnet_bind_uri (vnet_bind_uri_args_t *a)
{
  uri_main_t *um = &uri_main;
  vl_api_registration_t *regp;
  u8 * segment_name = 0;
  u8 * server_name;
  session_manager_main_t *smm = &session_manager_main;
  application_t *app = 0;
  u16 port_number_host_byte_order;
  stream_session_type_t sst = SESSION_TYPE_N_TYPES;
  unformat_input_t _input, *input= &_input;
  ip46_address_t ip46_address;
  u8 *fifo_name;
  session_manager_t *sm;
  int rv;

  ASSERT(a->uri && a->segment_name_length);

  /* Make sure ??? */
  a->uri = (char *)format (0, "%s%c", a->uri, 0);

  if (fifo_bind_table_lookup (um, a->uri))
    return VNET_API_ERROR_ADDRESS_IN_USE;

  unformat_init_string (input, a->uri, strlen (a->uri));
  /* If the URI doesn't parse, return an error */
  if (!unformat (input, "%U", unformat_vnet_uri, &ip46_address,
                 &sst, &port_number_host_byte_order, &fifo_name))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }

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

  if (sst == SESSION_TYPE_FIFO)
    goto uri_bind;

  /* Allocate and initialize stream server */
  app = application_new (smm, APP_SERVER, sst);
  sm = application_get_session_manager (smm, app);

  /* Add first segment */
  if ((rv = session_manager_add_first_segment (smm, sm, a->segment_size,
                                               &segment_name)))
    {
      /* If it failed, cleanup */
      application_del (smm, app);
      return rv;
    }

  /* Initialize stream server */
  app->api_client_index = a->api_client_index;
  app->flags = a->options[URI_OPTIONS_FLAGS];

  /* Callbacks */
  app->session_accept_callback = a->send_session_create_callback;
  app->session_delete_callback = stream_session_delete;
  app->session_clear_callback = a->send_session_clear_callback;
  app->builtin_server_rx_callback = a->builtin_server_rx_callback;
  app->add_segment_callback = a->add_segment_callback;

  /* Setup session manager */
  sm->add_segment_size = a->options[URI_OPTIONS_ADD_SEGMENT_SIZE];
  sm->rx_fifo_size = a->options[URI_OPTIONS_RX_FIFO_SIZE];
  sm->tx_fifo_size = a->options[URI_OPTIONS_TX_FIFO_SIZE];
  sm->add_segment = 1;

  /* Setup listen path down to transport */
  stream_server_listen (smm, app, &ip46_address, port_number_host_byte_order);

 uri_bind:

  fifo_bind_table_add (um, (u8 *)a->uri, server_name, segment_name,
                      a->api_client_index, a->accept_cookie);

  /*
   * Return values
   */

  ASSERT (vec_len(segment_name) <= 128);
  a->segment_name_length = vec_len(segment_name);
  memcpy (a->segment_name, segment_name, a->segment_name_length);
  a->server_event_queue_address = (u64) app->event_queue;

  vec_free (fifo_name);

  return 0;
}

int
vnet_unbind_uri (char * uri, u32 api_client_index)
{
  uri_main_t * um = &uri_main;
  session_manager_main_t * smm = &session_manager_main;
  application_t * ss;
  vl_api_registration_t *regp;
  u16 port_number_host_byte_order;
  stream_session_type_t sst = SESSION_TYPE_N_TYPES;
  unformat_input_t _input, *input = &_input;
  ip46_address_t ip46_address;
  u8 *fifo_name;
  uri_bind_table_entry_t *e;

  ASSERT(uri);

  /* Clean out the uri->server name mapping */
  e = fifo_bind_table_lookup (um, uri);
  if (!e)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  unformat_init_string (input, uri, strlen (uri));
  /* If the URI doesn't parse, return an error */
  if (!unformat (input, "%U", unformat_vnet_uri, &ip46_address, &sst,
                 &port_number_host_byte_order, &fifo_name))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* External client? */
  if (api_client_index != ~0)
    {
      regp = vl_api_client_index_to_registration (api_client_index);
      ASSERT(regp);
    }

  /*
   * Find the stream_server_t corresponding to the api client
   * $$$$ maybe add a hash table? There may only be three or four...
   */
  pool_foreach(ss, smm->applications, (
  {
    if (ss->api_client_index == api_client_index)
    goto found;
  }));

  /* Better never happen... */
  return VNET_API_ERROR_INVALID_VALUE_2;

  found:

  /* Clear the listener */
  if (sst != SESSION_TYPE_FIFO)
    stream_server_listen_stop (smm, ss);

  application_del (smm, ss);

  fifo_bind_table_del (um, e);

  return 0;
}

int
vnet_connect_uri (char *uri, u32 api_client_index, u64 *options,
                  char *segment_name, u32 *name_length, void *mp)
{
  session_manager_main_t *smm = &session_manager_main;
  unformat_input_t _input, *input= &_input;
  ip46_address_t ip46_address;
  u16 port;
  stream_session_type_t sst;
  u8 *fifo_name, is_ip4 = 0;
  stream_session_t *listener;
  application_t *ss;
  int rv;

  ASSERT(uri);

  /* TODO XXX connects table */

  memset(&ip46_address, 0, sizeof(ip46_address_t));
  unformat_init_string (input, uri, strlen (uri));

  if (!unformat (input, "%U", unformat_vnet_uri, &ip46_address,
                &sst, &port, &fifo_name))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* FIFO do its thing and return */
  if (SESSION_TYPE_FIFO == sst)
    {
      rv = vnet_connect_fifo_uri (uri, api_client_index, options, segment_name,
                                  name_length);
      vec_free(fifo_name);
      return rv;
    }

  /*
   * Figure out if connecting to a local server
   */

  listener = stream_session_lookup_listener (&ip46_address,
                                             clib_host_to_net_u16 (port), sst);

  /* Find the server */
  if (listener)
    {
      ss = pool_elt_at_index(smm->applications, listener->server_index);

      /*
       * Server is willing to have a direct fifo connection created
       * instead of going through the state machine, etc.
       */
      if (SESSION_TYPE_IP4_UDP == sst || SESSION_TYPE_IP4_TCP == sst)
        is_ip4 = 1;

      if (ss->flags & (URI_OPTIONS_FLAGS_USE_FIFO == 1))
        return application_connect_to_local_server (ss, &ip46_address, mp,
                                                      is_ip4);
    }

  /*
   * Not connecting to a local server. Create regular session
   */

  /* Allocate connect session manager if needed */
  if (smm->connect_manager_index[sst] == INVALID_INDEX)
    connect_manager_init(smm, sst);

  /* Notify transport */
  stream_session_open (smm, sst, &ip46_address, port, api_client_index);

  /* TODO */
  return VNET_API_ERROR_INVALID_VALUE;
}

int
vnet_disconnect_uri (u32 client_index, u32 session_index, u32 thread_index)
{
  session_manager_main_t * smm = &session_manager_main;
  stream_session_t * session;
  stream_session_t * pool;

  if (thread_index >= vec_len (smm->sessions))
    return VNET_API_ERROR_INVALID_VALUE;

  pool = smm->sessions[thread_index];

  if (pool_is_free_index (pool, session_index))
    return VNET_API_ERROR_INVALID_VALUE_2;

  session = pool_elt_at_index (smm->sessions[thread_index],
                               session_index);

  switch (session->session_type)
    {
    case SESSION_TYPE_IP4_UDP:
      stream_session_delete (smm, session);
      break;

    default:
      return VNET_API_ERROR_UNIMPLEMENTED;
    }
  return 0;
}

static clib_error_t *
uri_init (vlib_main_t * vm)
{
  uri_main_t * um = &uri_main;

  um->uri_bind_table_entry_by_name = hash_create_string (0, sizeof (uword));
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
