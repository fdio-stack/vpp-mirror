/* * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief BFD global declarations
 */

#ifndef __included_bfd_udp_h__
#define __included_bfd_udp_h__

#include <vppinfra/clib.h>
#include <vnet/adj/adj_types.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/bfd/bfd_api.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {

  u32 sw_if_index;
  ip46_address_t local_addr;
  ip46_address_t peer_addr;

}) bfd_udp_key_t;
/* *INDENT-ON* */

typedef struct
{
  bfd_udp_key_t key;

  adj_index_t adj_index;
} bfd_udp_session_t;

/* bfd udp echo packet trace capture */
typedef struct
{
  u32 len;
  u8 data[400];
} bfd_udp_echo_input_trace_t;

struct bfd_session_s;

int bfd_add_udp4_transport (vlib_main_t * vm, vlib_buffer_t * b,
			    const struct bfd_session_s *bs, int is_echo);
int bfd_add_udp6_transport (vlib_main_t * vm, vlib_buffer_t * b,
			    const struct bfd_session_s *bs, int is_echo);

/**
 * @brief check if the bfd udp layer is echo-capable at this time
 *
 * @return 1 if available, 0 otherwise
 */
int bfd_udp_is_echo_available (bfd_transport_e transport);

#endif /* __included_bfd_udp_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
