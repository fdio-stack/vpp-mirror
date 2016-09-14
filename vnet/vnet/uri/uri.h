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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <svm_fifo_segment.h>

typedef struct
{
  u8 * fifo_name;
  u8 * server_name;
  u8 * segment_name;
  u32 segment_size;
  u32 bind_client_index;
  u32 accept_cookie;
  u32 connect_client_index;
} fifo_bind_table_entry_t;

typedef struct
{
  /* Bind tables */
  /* Named rx/tx fifo pairs */
  fifo_bind_table_entry_t * fifo_bind_table;
  uword * fifo_bind_table_entry_by_name;
  
  /* Convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} uri_main_t;

extern uri_main_t uri_main;

int vnet_bind_uri (char * uri, u32 api_client_index, u32 accept_cookie
                   u32 segment_size, u64 *options, char *segment_name,
                   u32 *name_length);

int vnet_unbind_uri (char * uri, u32 api_client_index);

#endif /* __included_uri_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
