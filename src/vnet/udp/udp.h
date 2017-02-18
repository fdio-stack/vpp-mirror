/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#ifndef __included_udp_h__
#define __included_udp_h__

#include <vnet/ip/ip.h>
#include <vnet/session/transport.h>

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
      u32 session_type;
    };
    u64 as_u64[2];
  };
}) udp4_session_key_t;

typedef struct
{
  transport_connection_t connection;          /** must be first */

  /** ersatz MTU to limit fifo pushes to test data size */
  u32 mtu;
} udp_session_t;

typedef struct _udp_uri_main
{
  /* Per-worker thread udp connection pools */
  udp_session_t **udp_sessions;
  udp_session_t *udp_listeners;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ip4_main_t * ip4_main;
  ip6_main_t * ip6_main;
} udp_uri_main_t;

extern udp_uri_main_t udp_uri_main;

always_inline udp_uri_main_t *
vnet_get_udp_main ()
{
  return &udp_uri_main;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_udp_h__ */

