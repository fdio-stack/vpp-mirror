/*
 *------------------------------------------------------------------
 * dhcp_api.c - dhcp api
 *
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/dhcp/dhcp_proxy.h>
#include <vnet/dhcp/client.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                       \
_(DHCP_PROXY_CONFIG,dhcp_proxy_config)            \
_(DHCP_PROXY_DUMP,dhcp_proxy_dump)                \
_(DHCP_PROXY_DETAILS,dhcp_proxy_details)          \
_(DHCP_PROXY_SET_VSS,dhcp_proxy_set_vss)          \
_(DHCP_CLIENT_CONFIG, dhcp_client_config)


static void
vl_api_dhcp_proxy_set_vss_t_handler (vl_api_dhcp_proxy_set_vss_t * mp)
{
  vl_api_dhcp_proxy_set_vss_reply_t *rmp;
  int rv;

  rv = dhcp_proxy_set_vss ((mp->is_ipv6 ?
			    FIB_PROTOCOL_IP6 :
			    FIB_PROTOCOL_IP4),
			   ntohl (mp->tbl_id),
			   ntohl (mp->oui),
			   ntohl (mp->fib_id), (int) mp->is_add == 0);

  REPLY_MACRO (VL_API_DHCP_PROXY_SET_VSS_REPLY);
}


static void vl_api_dhcp_proxy_config_t_handler
  (vl_api_dhcp_proxy_config_t * mp)
{
  vl_api_dhcp_proxy_set_vss_reply_t *rmp;
  ip46_address_t src, server;
  int rv = -1;

  if (mp->is_ipv6)
    {
      clib_memcpy (&src.ip6, mp->dhcp_src_address, sizeof (src.ip6));
      clib_memcpy (&server.ip6, mp->dhcp_server, sizeof (server.ip6));

      rv = dhcp6_proxy_set_server (&server,
				   &src,
				   (u32) ntohl (mp->rx_vrf_id),
				   (u32) ntohl (mp->server_vrf_id),
				   (int) (mp->is_add == 0));
    }
  else
    {
      ip46_address_reset (&src);
      ip46_address_reset (&server);

      clib_memcpy (&src.ip4, mp->dhcp_src_address, sizeof (src.ip4));
      clib_memcpy (&server.ip4, mp->dhcp_server, sizeof (server.ip4));

      rv = dhcp4_proxy_set_server (&server,
				   &src,
				   (u32) ntohl (mp->rx_vrf_id),
				   (u32) ntohl (mp->server_vrf_id),
				   (int) (mp->is_add == 0));
    }


  REPLY_MACRO (VL_API_DHCP_PROXY_CONFIG_REPLY);
}

static void
vl_api_dhcp_proxy_dump_t_handler (vl_api_dhcp_proxy_dump_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  dhcp_proxy_dump ((mp->is_ip6 == 0 ?
		    FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4), q, mp->context);
}

void
dhcp_send_details (fib_protocol_t proto,
		   void *opaque,
		   u32 context,
		   const ip46_address_t * server,
		   const ip46_address_t * src,
		   u32 server_fib_id,
		   u32 rx_fib_id, u32 vss_fib_id, u32 vss_oui)
{
  vl_api_dhcp_proxy_details_t *mp;
  unix_shared_memory_queue_t *q = opaque;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_DHCP_PROXY_DETAILS);
  mp->context = context;

  mp->rx_vrf_id = htonl (rx_fib_id);
  mp->server_vrf_id = htonl (server_fib_id);
  mp->vss_oui = htonl (vss_oui);
  mp->vss_fib_id = htonl (vss_fib_id);

  mp->is_ipv6 = (proto == FIB_PROTOCOL_IP6);

  if (mp->is_ipv6)
    {
      memcpy (mp->dhcp_server, server, 16);
      memcpy (mp->dhcp_src_address, src, 16);
    }
  else
    {
      /* put the address in the first bytes */
      memcpy (mp->dhcp_server, &server->ip4, 4);
      memcpy (mp->dhcp_src_address, &src->ip4, 4);
    }
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}


static void
vl_api_dhcp_proxy_details_t_handler (vl_api_dhcp_proxy_details_t * mp)
{
  clib_warning ("BUG");
}

void
dhcp_compl_event_callback (u32 client_index, u32 pid, u8 * hostname,
			   u8 is_ipv6, u8 * host_address, u8 * router_address,
			   u8 * host_mac)
{
  unix_shared_memory_queue_t *q;
  vl_api_dhcp_compl_event_t *mp;

  q = vl_api_client_index_to_input_queue (client_index);
  if (!q)
    return;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->client_index = client_index;
  mp->pid = pid;
  mp->is_ipv6 = is_ipv6;
  clib_memcpy (&mp->hostname, hostname, vec_len (hostname));
  mp->hostname[vec_len (hostname) + 1] = '\n';
  clib_memcpy (&mp->host_address[0], host_address, 16);
  clib_memcpy (&mp->router_address[0], router_address, 16);

  if (NULL != host_mac)
    clib_memcpy (&mp->host_mac[0], host_mac, 6);

  mp->_vl_msg_id = ntohs (VL_API_DHCP_COMPL_EVENT);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void vl_api_dhcp_client_config_t_handler
  (vl_api_dhcp_client_config_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_dhcp_client_config_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = dhcp_client_config (vm, ntohl (mp->sw_if_index),
			   mp->hostname, mp->is_add, mp->client_index,
			   mp->want_dhcp_event ? dhcp_compl_event_callback :
			   NULL, mp->pid);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_DHCP_CLIENT_CONFIG_REPLY);
}

/*
 * dhcp_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_dhcp;
#undef _
}

static clib_error_t *
dhcp_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (dhcp_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
