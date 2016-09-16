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
#ifndef __included_udp_session_h__
#define __included_udp_session_h__

typedef enum
{
  UDP_SESSION_STATE_NONE,
  UDP_SESSION_STATE_CONNECTING,
  UDP_SESSION_STATE_READY,
  UDP_SESSION_STATE_DISCONNECTING,
} udp_session_state_t;

/* 16 octets */
typedef CLIB_PACKED(struct
{
  ip4_address_t src, dst;
  u16 src_port, dst_port;
  /* align by making this 4 octets even though its a 1-bit field */
  u32 is_tcp;
}) udp4_session_key_t;

typedef struct
{
  u8 state;
  /** ersatz MTU to limit fifo pushes to test data size */
  u32 mtu:

  /** session key */
  union 
  {
    udp4_session_key_t as_key;
    u64 as_u64[2];
  } key;
} udp4_session_t;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_udp_session_h__ */

