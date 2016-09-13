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
#ifndef __included_uri_h__
#define __included_uri_h__

/** @file
    URI handling, bind tables
*/

uri_main_t uri_main;

/* types: fifo, tcp4, udp4, tcp6, udp6 */

int vnet_bind_fifo_uri (char *uri, u32 api_client_index, u32 accept_cookie)
{
  uri_main_t * um = &uri_main;
  fifo_bind_table_entry_t * e;
  vl_api_registration_t *regp;
  uword * p;
  u8 * server_name;

  p = hash_get_mem (um->fifo_bind_table_entry_by_name, uri);

  if (p)
    return VNET_API_ERROR_ADDRESS_IN_USE;

  /* External client? */
  if (api_cient_index != ~0)
    {
      regp = vl_api_client_index_to_registration (api_client_index);
      ASSERT(regp);
      server_name = format (0, "%s%c", regp->name, 0);
    }
  else
    server_name = format (0, "<internal>%c", 0);

  pool_get (um->fifo_bind_table, e);
  memset (e, 0, sizeof (*e));

  e->fifo_name = format (0, "%s%c", uri, 0);
  e->server_name = servier_name;
  e->client_index = api_client_index;
  e->accept_cookie = accept_cookie;

  hash_set_mem (um->fifo_bind_table_entry_by_name, e->fifo_name, 
                e - um->fifo_bind_table);
  return 0;
}

int vnet_unbind_fifo_uri (char *uri, u32 api_client_index)
{
  uri_main_t * um = &uri_main;
  fifo_bind_table_entry_t * e;
  vl_api_registration_t *regp;
  uword * p;
  u8 * server_name;

  p = hash_get_mem (um->fifo_bind_table_entry_by_name, uri);

  if (!p)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  e = pool_elt_at_index (um->fifo_bind_table, p[0]);

  /* Just in case */
  if (e->client_index != api_client_index)
    return VNET_API_ERROR_INVALID_VALUE;

  /* $$$ should we tear down connections? */

  hash_unset_mem (um->fifo_bind_table_entry_by_name, e->fifo_name);
  
  vec_free (e->fifo_name);
  vec_free (e->server_name);
  pool_put (um->fifo_bind_table, e);
  return 0;
}

int vnet_bind_uri (char * uri, u32 api_client_index, u32 accept_cookie
                   u64 *options)
{
  ASSERT(uri);

  /* Mumble top-level decode mumble */
  if (uri[0] == 'f')
    return vnet_bind_fifo_uri (uri, api_client_index, accept_cookie);
  else
    return VNET_API_ERROR_UNKNOWN_URI_TYPE;
}

int vnet_ubind_uri (char * uri, u32 api_client_index)
{
  ASSERT(uri);

  /* Mumble top-level decode mumble */
  if (uri[0] == 'f')
    return vnet_ubind_fifo_uri (uri, api_client_index);
  else
    return VNET_API_ERROR_UNKNOWN_URI_TYPE;
}

static clib_error_t *
uri_init (vlib_main_t * vm)
{
  uri_main_t * um = &uri_main;

  um->fifo_bind_table_entry_by_name = hash_create_string (0, sizeof (uword));
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
