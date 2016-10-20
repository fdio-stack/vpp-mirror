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

typedef struct _transport_session transport_session_t;

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
}) v4_session_key_t;

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
}) v6_session_key_t;

typedef void
(*tp_session_create) (void *);

typedef void
(*tp_session_delete) (transport_session_t * s);

/** TODO decide if fwd slowdown is worth generalizing uri_*_node */
typedef struct _transport_session_vft
{
  tp_session_create create;
  tp_session_delete delete;
} transport_session_vft_t;

/*
 * Protocol independent transport properties associated to a session
 */
struct _transport_session
{
  ip46_address_t remote_ip;
  ip46_address_t local_ip;
  u16 local_port;
  u16 remote_port;
  u8 proto;                     /**< transport protocol id */

  u8 state;                     /**< transport session state */
  u32 session_index;            /**< parent session index */
  u32 transport_session_index;  /**< index in transport pool */

  const transport_session_vft_t *ts_vft;   /**< virtual function table */

  /** Macros for 'derived classes' where base is named "session" */
#define s_lcl_ip4 session.local_ip.ip4
#define s_rmt_ip4 session.remote_ip.ip4
#define s_lcl_ip6 session.local_ip.ip6
#define s_rmt_ip6 session.remote_ip.ip6
#define s_lcl_port session.local_port
#define s_rmt_port session.remote_port
#define s_proto session.proto
#define s_s_index session.session_index
#define s_t_index session.transport_session_index
#define s_vft session.ts_vft

};


#endif /* VNET_VNET_URI_TRANSPORT_H_ */
