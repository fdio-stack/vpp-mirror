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
#include <svm/svm_fifo_segment.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>

typedef struct
{
  /* Convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} uri_main_t;

extern uri_main_t uri_main;

typedef struct
{
  char *uri;
  u32 api_client_index;
  u32 accept_cookie;
  u32 segment_size;
  u64 *options;
  session_cb_vft_t *session_cb_vft;

  /*
   * Results
   */
  char *segment_name;
  u32 segment_name_length;
  u64 server_event_queue_address;
} vnet_bind_uri_args_t;

typedef struct _connect_uri_args
{
  char *uri;
  u32 api_client_index;
  u64 *options;
  session_cb_vft_t *session_cb_vft;

  /* Used for redirects */
  void *mp;
} vnet_connect_uri_args_t;

/* Bind / connect options */
typedef enum
{
  URI_OPTIONS_FLAGS,
  URI_OPTIONS_ADD_SEGMENT_SIZE,
  URI_OPTIONS_RX_FIFO_SIZE,
  URI_OPTIONS_TX_FIFO_SIZE,
  URI_OPTIONS_N_OPTIONS
} uri_options_index_t;

/** Server can handle delegated connect requests from local clients */
#define URI_OPTIONS_FLAGS_USE_FIFO	(1<<0)

/** Server wants vpp to add segments when out of memory for fifos */
#define URI_OPTIONS_FLAGS_ADD_SEGMENT   (1<<1)

#define VNET_CONNECT_URI_REDIRECTED	123

int
vnet_bind_uri (vnet_bind_uri_args_t *);
int
vnet_unbind_uri (char * uri, u32 api_client_index);
int
vnet_connect_uri (vnet_connect_uri_args_t *a);
int
vnet_disconnect_uri (u32 client_index, u32 session_index, u32 thread_index);

int
uri_api_session_not_valid (u32 session_index, u32 thread_index);

#endif /* __included_uri_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
