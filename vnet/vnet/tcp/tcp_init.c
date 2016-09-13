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

#include <vlib/vlib.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>

static clib_error_t *
tcp_init (vlib_main_t * vm)
{
  ip_main_t * im = &ip_main;
  ip_protocol_info_t * pi;
  clib_error_t * error;

  error = vlib_call_init_function (vm, ip_main_init);

  if (! error)
    {
      pi = ip_get_protocol_info (im, IP_PROTOCOL_TCP);
      if (pi == 0)
          return clib_error_return (0, "TCP protocol info AWOL");
      pi->format_header = format_tcp_header;
      //pi->unformat_pg_edit = unformat_pg_tcp_header;
    }

  return 0;
}

VLIB_INIT_FUNCTION (tcp_init);
