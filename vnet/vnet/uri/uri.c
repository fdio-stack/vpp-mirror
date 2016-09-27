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
#include "uri.h"
#include <vlibmemory/api.h>

/** @file
    URI handling, bind tables
*/

uri_main_t uri_main;
stream_server_main_t stream_server_main;

/* types: fifo, tcp4, udp4, tcp6, udp6 */

u8 * format_bind_table_entry (u8 * s, va_list * args)
{
  uri_bind_table_entry_t * e = va_arg (*args, uri_bind_table_entry_t *);
  int verbose = va_arg (*args, int);

  if (e == 0)
    {
      if (verbose)
        s = format (s, "%-15s%-15s%-20s%-10s%-10s",
                    "URI", "Server", "Segment", "API Client", "Cookie");
      else
        s = format (s, "%-15s%-15s",
                    "URI", "Server");
      return s;
    }

  if (verbose)
    s = format (s, "%-15s%-15s%-20s%-10d%-10d",
                e->bind_name, e->server_name, e->segment_name,
                e->bind_client_index,
                e->accept_cookie);
  else
    s = format (s, "%-15s%-15s", e->bind_name, e->server_name);
  return s;
}

/**** fifo uri */

int vnet_bind_fifo_uri (vnet_bind_uri_args_t *a)
{
  uri_main_t * um = &uri_main;
  uri_bind_table_entry_t * e;
  vl_api_registration_t *regp;
  uword * p;
  u8 * server_name, * segment_name;

  ASSERT(a->segment_name_length);

  p = hash_get_mem (um->uri_bind_table_entry_by_name, a->uri);

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

  /* Unique segment name, per vpp instance */
  segment_name = format (0, "%d-%s%c", getpid(), a->uri, 0);
  ASSERT (vec_len(a->segment_name) <= 128);
  a->segment_name_length = vec_len(segment_name);
  memcpy (a->segment_name, segment_name, a->segment_name_length);

  pool_get (um->fifo_bind_table, e);
  memset (e, 0, sizeof (*e));

  e->bind_name = format (0, "%s%c", a->uri, 0);
  e->server_name = server_name;
  e->segment_name = segment_name;
  e->bind_client_index = a->api_client_index;
  e->accept_cookie = a->accept_cookie;

  hash_set_mem (um->uri_bind_table_entry_by_name, e->bind_name, 
                e - um->fifo_bind_table);
  return 0;
}

int vnet_unbind_fifo_uri (char *uri, u32 api_client_index)
{
  uri_main_t * um = &uri_main;
  uri_bind_table_entry_t * e;
  uword * p;

  p = hash_get_mem (um->uri_bind_table_entry_by_name, uri);

  if (!p)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  e = pool_elt_at_index (um->fifo_bind_table, p[0]);

  /* Just in case */
  if (e->bind_client_index != api_client_index)
    return VNET_API_ERROR_INVALID_VALUE;

  /* $$$ should we tear down connections? */

  hash_unset_mem (um->uri_bind_table_entry_by_name, e->bind_name);
  
  vec_free (e->bind_name);
  vec_free (e->server_name);
  vec_free (e->segment_name);
  pool_put (um->fifo_bind_table, e);
  return 0;
}

int vnet_connect_fifo_uri (char *uri, u32 api_client_index,
                           u64 * options, char *segment_name_arg, 
                           u32 * segment_name_length)
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

int vnet_bind_uri (vnet_bind_uri_args_t *a)
{
  ASSERT(a->uri);

  /* Mumble top-level decode mumble */
  if (a->uri[0] == 'f')
    return vnet_bind_fifo_uri (a);
  else if (a->uri[0] == 'u' && a->uri[3] == '4')
    return vnet_bind_udp4_uri (a);
  else
    return VNET_API_ERROR_UNKNOWN_URI_TYPE;
}

int vnet_unbind_uri (char * uri, u32 api_client_index)
{
  ASSERT(uri);

  /* Mumble top-level decode mumble */
  if (uri[0] == 'f')
    return vnet_unbind_fifo_uri (uri, api_client_index);
  else if (uri[0] == 'u' && uri[3] == '4')
    return vnet_unbind_udp4_uri (uri, api_client_index);
  else
    return VNET_API_ERROR_UNKNOWN_URI_TYPE;
}

int vnet_connect_uri (char * uri, u32 api_client_index,
                      u64 *options, char *segment_name, u32 *name_length)
{
  ASSERT(uri);

  /* Mumble top-level decode mumble */
  if (uri[0] == 'f')
    return vnet_connect_fifo_uri (uri, api_client_index, options, 
                                  segment_name, name_length);
  else
    return VNET_API_ERROR_UNKNOWN_URI_TYPE;
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

static clib_error_t * 
stream_server_init (vlib_main_t * vm)
{
  u32 num_threads;
  vlib_thread_main_t *tm = &vlib_thread_main;
  stream_server_main_t * ssm = &stream_server_main;

  num_threads = 1 /* main thread */ + tm->n_eal_threads;

  if (num_threads < 1)
    return clib_error_return (0, "n_thread_stacks not set");

  
  /* $$$ config parameters */
  svm_fifo_segment_init(0x200000000ULL /* first segment base VA */, 
                        20 /* timeout in seconds */);

  /* configure per-thread ** vectors */
  vec_validate (ssm->sessions, num_threads - 1);
  vec_validate (ssm->session_indices_to_enqueue_by_thread, num_threads-1);
  vec_validate (ssm->tx_buffers, num_threads - 1);
  vec_validate (ssm->fifo_events, num_threads - 1);
  vec_validate (ssm->current_enqueue_epoch, num_threads - 1);
  vec_validate (ssm->vpp_event_queues, num_threads - 1);

  clib_bihash_init_16_8 (&ssm->v4_session_hash, "v4 session table",
                         16 /* $$$$ config parameter nbuckets */,
                         (32<<20) /*$$$ config parameter table size */);
  
  ssm->vlib_main = vm;
  ssm->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (stream_server_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
