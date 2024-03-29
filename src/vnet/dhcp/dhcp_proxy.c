/*
 * proxy_node.c: common dhcp v4 and v6 proxy node processing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vnet/dhcp/dhcp_proxy.h>
#include <vnet/fib/fib_table.h>

/**
 * @brief Shard 4/6 instance of DHCP main
 */
dhcp_proxy_main_t dhcp_proxy_main;

void
dhcp_proxy_walk (fib_protocol_t proto,
                 dhcp_proxy_walk_fn_t fn,
                 void *ctx)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  dhcp_server_t * server;
  u32 server_index, i;

  vec_foreach_index (i, dpm->dhcp_server_index_by_rx_fib_index[proto])
  {
      server_index = dpm->dhcp_server_index_by_rx_fib_index[proto][i];
      if (~0 == server_index)
          continue;

      server = pool_elt_at_index (dpm->dhcp_servers[proto], server_index);

      if (!fn(server, ctx))
          break;
    }
}

void
dhcp_vss_walk (fib_protocol_t proto,
               dhcp_vss_walk_fn_t fn,
               void *ctx)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  dhcp_vss_t * vss;
  u32 vss_index, i;
  fib_table_t *fib;


  vec_foreach_index (i, dpm->vss_index_by_rx_fib_index[proto])
  {
      vss_index = dpm->vss_index_by_rx_fib_index[proto][i];
      if (~0 == vss_index)
          continue;

      vss = pool_elt_at_index (dpm->vss[proto], vss_index);

      fib = fib_table_get(i, proto);

      if (!fn(vss, fib->ft_table_id, ctx))
          break;
    }
}

int
dhcp_proxy_server_del (fib_protocol_t proto,
                       u32 rx_fib_index)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  dhcp_server_t * server = 0;
  int rc = 0;

  server = dhcp_get_server(dpm, rx_fib_index, proto);

  if (NULL == server)
  {
      rc = VNET_API_ERROR_NO_SUCH_ENTRY;
  }
  else
  {
      /* Use the default server again.  */
      dpm->dhcp_server_index_by_rx_fib_index[proto][rx_fib_index] = ~0;

      fib_table_unlock (server->server_fib_index, proto);

      pool_put (dpm->dhcp_servers[proto], server);
  }

  return (rc);
}

int
dhcp_proxy_server_add (fib_protocol_t proto,
                       ip46_address_t *addr,
                       ip46_address_t *src_address,
                       u32 rx_fib_index,
                       u32 server_table_id)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  dhcp_server_t * server = 0;
  int new = 0;

  server = dhcp_get_server(dpm, rx_fib_index, proto);

  if (NULL == server)
  {
      vec_validate_init_empty(dpm->dhcp_server_index_by_rx_fib_index[proto],
                              rx_fib_index,
                              ~0);

      pool_get (dpm->dhcp_servers[proto], server);
      memset (server, 0, sizeof (*server));
      new = 1;

      dpm->dhcp_server_index_by_rx_fib_index[proto][rx_fib_index] =
          server - dpm->dhcp_servers[proto];

      server->rx_fib_index = rx_fib_index;
      server->server_fib_index = 
          fib_table_find_or_create_and_lock(proto, server_table_id);
  }
  else
  {
      /* modify, may need to swap server FIBs */
      u32 tmp_index;

      tmp_index = fib_table_find(proto, server_table_id);

      if (tmp_index != server->server_fib_index)
      {
          tmp_index = server->server_fib_index;

          /* certainly swapping if the fib doesn't exist */
          server->server_fib_index = 
              fib_table_find_or_create_and_lock(proto, server_table_id);
          fib_table_unlock (tmp_index, proto);
      }
  }

  server->dhcp_server = *addr;
  server->dhcp_src_address = *src_address;

  return (new);
}

typedef struct dhcp4_proxy_dump_walk_ctx_t_
{
    fib_protocol_t proto;
    void *opaque;
    u32 context;
} dhcp_proxy_dump_walk_cxt_t;

static int
dhcp_proxy_dump_walk (dhcp_server_t *server,
                      void *arg)
{
  dhcp_proxy_dump_walk_cxt_t *ctx = arg;
  fib_table_t *s_fib, *r_fib;
  dhcp_vss_t *v;

  v = dhcp_get_vss_info(&dhcp_proxy_main,
                        server->rx_fib_index,
                        ctx->proto);

  s_fib = fib_table_get(server->server_fib_index, ctx->proto);
  r_fib = fib_table_get(server->rx_fib_index, ctx->proto);

  dhcp_send_details(ctx->proto,
                    ctx->opaque,
                    ctx->context,
                    &server->dhcp_server,
                    &server->dhcp_src_address,
                    s_fib->ft_table_id,
                    r_fib->ft_table_id,
                    (v ? v->fib_id : 0),
                    (v ? v->oui : 0));

  return (1);
}

void
dhcp_proxy_dump (fib_protocol_t proto,
                 void *opaque,
                 u32 context)
{
    dhcp_proxy_dump_walk_cxt_t ctx =  {
        .proto = proto,
        .opaque = opaque,
        .context = context,
    };
    dhcp_proxy_walk(proto, dhcp_proxy_dump_walk, &ctx);
}

int
dhcp_vss_show_walk (dhcp_vss_t *vss,
                    u32 rx_table_id,
                    void *ctx)
{
    vlib_main_t * vm = ctx;

    vlib_cli_output (vm, "%=6d%=6d%=12d",
                     rx_table_id,
                     vss->oui,
                     vss->fib_id);

    return (1);
}

int dhcp_proxy_set_vss (fib_protocol_t proto,
                        u32 tbl_id,
                        u32 oui,
                        u32 fib_id, 
                        int is_del)
{
  dhcp_proxy_main_t *dm = &dhcp_proxy_main;
  dhcp_vss_t *v = NULL;
  u32  rx_fib_index;
  int rc = 0;
  
  rx_fib_index = fib_table_find_or_create_and_lock(proto, tbl_id);
  v = dhcp_get_vss_info(dm, rx_fib_index, proto);

  if (NULL != v)
  {
      if (is_del)
      {
          /* release the lock held on the table when the VSS
           * info was created */
          fib_table_unlock (rx_fib_index, proto);

          pool_put (dm->vss[proto], v);
          dm->vss_index_by_rx_fib_index[proto][rx_fib_index] = ~0;
      }
      else
      {
          /* this is a modify */
          v->fib_id = fib_id;
          v->oui = oui;
      }
  }
  else
  {
      if (is_del)
          rc = VNET_API_ERROR_NO_SUCH_ENTRY;
      else
      {
          /* create a new entry */
          vec_validate_init_empty(dm->vss_index_by_rx_fib_index[proto],
                                  rx_fib_index, ~0);

          /* hold a lock on the table whilst the VSS info exist */
          fib_table_lock (rx_fib_index, proto);

          pool_get (dm->vss[proto], v);
          v->fib_id = fib_id;
          v->oui = oui;
          dm->vss_index_by_rx_fib_index[proto][rx_fib_index] =
              v - dm->vss[proto];
      }
  }

  /* Release the lock taken during the create_or_lock at the start */
  fib_table_unlock (rx_fib_index, proto);
  
  return (rc);
}
