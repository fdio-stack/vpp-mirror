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

#ifndef VNET_VNET_URI_TRANSPORT_H_
#define VNET_VNET_URI_TRANSPORT_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

/* 16 octets */
typedef CLIB_PACKED (struct
{
  union
  {
    struct
    {
      ip4_address_t src;
      ip4_address_t dst;
      u16 src_port;
      u16 dst_port;
      /* align by making this 4 octets even though its a 1-bit field
       * NOTE: avoid key overlap with other transports that use 5 tuples for
       * session identification.
       */
      u32 proto;
    };
    u64 as_u64[2];
  };
}) v4_connection_key_t;

typedef CLIB_PACKED(struct
{
  union
  {
    struct
    {
      /* 48 octets */
      ip6_address_t src;
      ip6_address_t dst;
      u16 src_port;
      u16 dst_port;
      u32 proto;
      u8 unused_for_now [8];
    };
    u64 as_u64[6];
  };
}) v6_connection_key_t;

typedef struct _transport_endpoint
{
  ip46_address_t ip;
  u16 port;
} transport_endpoint_t;

typedef clib_bihash_24_8_t transport_endpoint_table_t;

#define TRANSPORT_ENDPOINT_INVALID_INDEX ((u32)~0)

u32
transport_endpoint_lookup (transport_endpoint_table_t *ht, ip46_address_t *ip,
                           u16 port);
void
transport_endpoint_table_add (transport_endpoint_table_t *ht,
                              transport_endpoint_t *te, u32 value);
void
transport_endpoint_table_del (transport_endpoint_table_t *ht,
                              transport_endpoint_t *te);
/*
 * Protocol independent transport properties associated to a session
 */
typedef struct _transport_connection
{
  ip46_address_t rmt_ip;        /**< Remote IP */
  ip46_address_t lcl_ip;        /**< Local IP */
  u16 lcl_port;                 /**< Local port */
  u16 rmt_port;                 /**< Remote port */
  u8 proto;                     /**< Transport protocol id */

  u32 s_index;                  /**< Parent session index */
  u32 c_index;                  /**< Connection index in transport pool */
  u8 is_ip4;                    /**< Flag if IP4 connection */
  u32 thread_index;             /**< Worker-thread index */

  /** Macros for 'derived classes' where base is named "connection" */
#define c_lcl_ip connection.lcl_ip
#define c_rmt_ip connection.rmt_ip
#define c_lcl_ip4 connection.lcl_ip.ip4
#define c_rmt_ip4 connection.rmt_ip.ip4
#define c_lcl_ip6 connection.lcl_ip.ip6
#define c_rmt_ip6 connection.rmt_ip.ip6
#define c_lcl_port connection.lcl_port
#define c_rmt_port connection.rmt_port
#define c_proto connection.proto
#define c_state connection.state
#define c_s_index connection.s_index
#define c_c_index connection.c_index
#define c_is_ip4 connection.is_ip4
#define c_thread_index connection.thread_index
} transport_connection_t;

typedef u32
(*tp_application_bind) (vlib_main_t *, u32, ip46_address_t *, u16);

typedef u32
(*tp_application_unbind) (vlib_main_t *, u32);

typedef u32
(*tp_application_send) (transport_connection_t *tconn, vlib_buffer_t *b);

typedef u8 *
(*tp_connection_format) (u8 *s, va_list *args);

typedef transport_connection_t *
(*tp_connection_get) (u32 conn_index, u32 my_thread_index);

typedef transport_connection_t *
(*tp_listen_connection_get) (u32 conn_index);

typedef transport_connection_t *
(*tp_half_open_connection_get) (u32 conne_index);

typedef void
(*tp_connection_close) (u32 conn_index, u32 my_thread_index);

typedef int
(*tp_connection_open) (ip46_address_t *addr, u16 port_host_byte_order);

typedef u16
(*tp_connection_snd_mss) (transport_connection_t *tc);

/*
 * Transport protocol virtual function table
 */
typedef struct _transport_proto_vft
{
  tp_application_bind bind;
  tp_application_unbind unbind;
  tp_application_send push_header;
  tp_connection_format format_connection;
  tp_connection_get get_connection;
  tp_listen_connection_get get_listener;
  tp_half_open_connection_get get_half_open;
  tp_connection_close delete;
  tp_connection_open open;
  tp_connection_snd_mss send_mss;
} transport_proto_vft_t;

#endif /* VNET_VNET_URI_TRANSPORT_H_ */