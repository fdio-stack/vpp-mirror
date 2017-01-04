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

typedef struct _transport_connection transport_connection_t;

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

/*
 * Protocol independent transport properties associated to a session
 */
struct _transport_connection
{
  ip46_address_t remote_ip;
  ip46_address_t local_ip;
  u16 local_port;
  u16 remote_port;
  u8 proto;                     /**< Transport protocol id */

  u8 state;                     /**< Transport session state */
  u32 session_index;            /**< Parent session index */
  u32 connection_index;         /**< Index in transport pool */
  u8 is_ip4;                    /**< Flag if IP4 connection */
  u32 thread_index;             /**< Worker-thread index */

  /** Macros for 'derived classes' where base is named "connection" */
#define c_lcl_ip4 connection.local_ip.ip4
#define c_rmt_ip4 connection.remote_ip.ip4
#define c_lcl_ip6 connection.local_ip.ip6
#define c_rmt_ip6 connection.remote_ip.ip6
#define c_lcl_port connection.local_port
#define c_rmt_port connection.remote_port
#define c_proto connection.proto
#define c_state connection.state
#define c_s_index connection.session_index
#define c_c_index connection.connection_index
#define c_vft connection.ts_vft
#define c_is_ip4 connection.is_ip4
#define c_thread_index connection.thread_index
};


#endif /* VNET_VNET_URI_TRANSPORT_H_ */
