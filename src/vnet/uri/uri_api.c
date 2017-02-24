/*
 * Copyright (c) 2015-2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/uri/uri.h>
#include <vnet/session/application.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs             /* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun            /* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_uri_api_msg                                             \
_(BIND_URI, bind_uri)                                                   \
_(UNBIND_URI, unbind_uri)                                               \
_(CONNECT_URI, connect_uri)                                             \
_(MAP_ANOTHER_SEGMENT_REPLY, map_another_segment_reply)                 \
_(ACCEPT_SESSION_REPLY, accept_session_reply)                           \
_(DISCONNECT_SESSION, disconnect_session)                               \
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)                   \

static int
send_session_accept_callback (stream_session_t *s)
{
  vl_api_accept_session_t * mp;
  unix_shared_memory_queue_t * q, *vpp_queue;
  application_t *server = application_get (s->app_index);

  q = vl_api_client_index_to_input_queue (server->api_client_index);
  vpp_queue = session_manager_get_vpp_event_queue (s->session_thread_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_ACCEPT_SESSION);

  /* Note: session_type is the first octet in all types of sessions */

  mp->accept_cookie = server->accept_cookie;
  mp->server_rx_fifo = (u64) s->server_rx_fifo;
  mp->server_tx_fifo = (u64) s->server_tx_fifo;
  mp->session_thread_index = s->session_thread_index;
  mp->session_index = s->session_index;
  mp->session_type = s->session_type;
  mp->vpp_event_queue_address = (u64) vpp_queue;
  vl_msg_api_send_shmem (q, (u8 *) & mp);

  return 0;
}

static void
send_session_delete_callback (stream_session_t * s)
{
  clib_warning ("not finished");
}

static int
send_add_segment_callback (u32 api_client_index, const u8 *segment_name,
                           u32 segment_size)
{
  vl_api_map_another_segment_t * mp;
  unix_shared_memory_queue_t * q;

  q = vl_api_client_index_to_input_queue (api_client_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset(mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_MAP_ANOTHER_SEGMENT);
  mp->segment_size = segment_size;
  strncpy ((char *)mp->segment_name, (char *)segment_name,
           sizeof (mp->segment_name)-1);

  vl_msg_api_send_shmem (q, (u8 *) & mp);

  return 0;
}

static void
send_session_clear_callback (stream_session_t *s)
{
  vl_api_accept_session_t * mp;
  unix_shared_memory_queue_t * q;
  application_t *app = application_get (s->app_index);

  q = vl_api_client_index_to_input_queue (app->api_client_index);

  if (!q)
    return;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_DISCONNECT_SESSION);

  mp->session_thread_index = s->session_thread_index;
  mp->session_index = s->session_index;
  vl_msg_api_send_shmem (q, (u8 *) & mp);

}

/**
 * Redirect a connect_uri message to the indicated server.
 * Only sent if the server has bound the related port with
 * URI_OPTIONS_FLAGS_USE_FIFO
 */
static int
redirect_connect_uri_callback (u32 server_api_client_index, void * mp_arg)
{
  vl_api_connect_uri_t * mp = mp_arg;
  unix_shared_memory_queue_t * server_q, * client_q;
  vlib_main_t * vm = vlib_get_main();
  f64 timeout = vlib_time_now (vm) + 0.5;
  int rv = 0;

  server_q = vl_api_client_index_to_input_queue (server_api_client_index);

  if (!server_q)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  client_q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!client_q)
    {
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto out;
    }

  /* Tell the server the client's API queue address, so it can reply */
  mp->client_queue_address = (u64) client_q;

  /*
   * Bounce message handlers MUST NOT block the data-plane.
   * Spin waiting for the queue lock, but
   */

  while (vlib_time_now (vm) < timeout)
    {
    rv = unix_shared_memory_queue_add (server_q, (u8 *)&mp, 1 /*nowait*/);
    switch (rv)
      {
        /* correctly enqueued */
      case 0:
        return VNET_CONNECT_URI_REDIRECTED;

        /* continue spinning, wait for pthread_mutex_trylock to work */
      case -1:
        continue;

        /* queue stuffed, drop the msg */
      case -2:
        rv = VNET_API_ERROR_QUEUE_FULL;
        goto out;
      }
    }
 out:
  /* Dispose of the message */
  vl_msg_api_free (mp);
  return rv;
}

static int
send_session_connected_callback (stream_session_t *s, u8 is_fail)
{
  vl_api_connect_uri_reply_t * mp;
  unix_shared_memory_queue_t * q;
  application_t *app = application_get (s->app_index);
  u8 *seg_name;
  unix_shared_memory_queue_t *vpp_queue;

  q = vl_api_client_index_to_input_queue (app->api_client_index);
  vpp_queue = session_manager_get_vpp_event_queue (s->session_thread_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_CONNECT_URI_REPLY);

  mp->retval = is_fail;
  if (!is_fail)
    {
      mp->server_rx_fifo = (u64) s->server_rx_fifo;
      mp->server_tx_fifo = (u64) s->server_tx_fifo;
      mp->session_thread_index = s->session_thread_index;
      mp->session_index = s->session_index;
      mp->session_type = s->session_type;
      mp->vpp_event_queue_address = (u64) vpp_queue;
      mp->client_event_queue_address = (u64) app->event_queue;

      session_manager_get_segment_info (s->server_segment_index, &seg_name,
                                        &mp->segment_size);
      mp->segment_name_length = vec_len(seg_name);
      if (mp->segment_name_length)
        clib_memcpy (mp->segment_name, seg_name, mp->segment_name_length);
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);

  /* Remove client if connect failed */
  if (is_fail)
    application_del (app);

  return 0;
}

static session_cb_vft_t session_cb_vft = {
    .session_accept_callback = send_session_accept_callback,
    .session_delete_callback = send_session_delete_callback,
    .session_clear_callback = send_session_clear_callback,
    .session_connected_callback = send_session_connected_callback,
    .add_segment_callback = send_add_segment_callback,
    .redirect_connect_callback = redirect_connect_uri_callback
};

static void
vl_api_bind_uri_t_handler (vl_api_bind_uri_t * mp)
{
  vl_api_bind_uri_reply_t * rmp;
  vnet_bind_uri_args_t _a, *a = & _a;
  char segment_name[128];
  u32 segment_name_length;
  int rv;

  _Static_assert(sizeof(u64) * URI_OPTIONS_N_OPTIONS <= sizeof (mp->options),
                 "Out of options, fix api message definition");

  segment_name_length = ARRAY_LEN(segment_name);

  memset (a, 0, sizeof (*a));

  a->uri = (char *) mp->uri;
  a->api_client_index = mp->client_index;
  a->accept_cookie = mp->accept_cookie;
  a->segment_size = mp->initial_segment_size;
  a->options = mp->options;
  a->segment_name = segment_name;
  a->segment_name_length = segment_name_length;
  a->session_cb_vft = &session_cb_vft;

  rv = vnet_bind_uri (a);

  REPLY_MACRO2 (VL_API_BIND_URI_REPLY,
  ({
    rmp->retval = rv;
    if (!rv)
      {
        rmp->segment_name_length = 0;
        /* $$$$ policy? */
        rmp->segment_size = mp->initial_segment_size;
        if (segment_name_length)
          {
            memcpy(rmp->segment_name, segment_name, segment_name_length);
            rmp->segment_name_length = segment_name_length;
          }
        rmp->server_event_queue_address = a->server_event_queue_address;
      }
  }));
}

static void
vl_api_unbind_uri_t_handler (vl_api_unbind_uri_t * mp)
{
  vl_api_unbind_uri_reply_t * rmp;
  int rv;

  rv = vnet_unbind_uri ((char *) mp->uri, mp->client_index);

  REPLY_MACRO (VL_API_UNBIND_URI_REPLY);
}

static void
vl_api_connect_uri_t_handler (vl_api_connect_uri_t * mp)
{
  vnet_connect_uri_args_t _a, *a= &_a;

  a->uri = (char *) mp->uri;
  a->api_client_index = mp->client_index;
  a->options = mp->options;
  a->session_cb_vft = &session_cb_vft;

  vnet_connect_uri (a);
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  vl_api_disconnect_session_reply_t * rmp;
  int rv;

  if (!(rv = uri_api_session_not_valid (mp->session_index,
                                       mp->session_thread_index)))
    rv = vnet_disconnect_uri (mp->client_index, mp->session_index,
                              mp->session_thread_index);

  REPLY_MACRO (VL_API_DISCONNECT_SESSION_REPLY);
}

static void
vl_api_disconnect_session_reply_t_handler (
    vl_api_disconnect_session_reply_t * mp)
{
  int rv;

  if (!(rv = uri_api_session_not_valid (mp->session_index,
                                       mp->session_thread_index)))
    return;

  /* Client objected to clearing the session, log and continue */
  if (mp->retval)
    {
      clib_warning ("client retval %d", mp->retval);
      return;
    }

  rv = vnet_disconnect_uri (mp->client_index, mp->session_index,
                            mp->session_thread_index);

  if (rv)
    clib_warning ("vpp retval %d", rv);
}

static void
vl_api_map_another_segment_reply_t_handler (
    vl_api_map_another_segment_reply_t * mp)
{
  clib_warning("not implemented");
}

static void
vl_api_accept_session_reply_t_handler (vl_api_accept_session_reply_t *mp)
{
  application_t * server;
  stream_session_t * s;
  int rv;

  if (uri_api_session_not_valid (mp->session_index, mp->session_thread_index))
    return;

  s = stream_session_get (mp->session_index, mp->session_thread_index);
  rv = mp->retval;

  if (rv)
    {
      /* Server isn't interested, kill the session */
      server = application_get (s->app_index);
      server->cb_fns.session_delete_callback (s);
      return;
    }

  s->session_state = SESSION_STATE_READY;
}

#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_uri;
#undef _
}

/*
 * uri_api_hookup
 * Add uri's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../open-repo/vlib/memclnt_vlib.c:memclnt_process()
 */
static clib_error_t *
uri_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_uri_api_msg;
#undef _

  /*
   * Messages which bounce off the data-plane to
   * an API client. Simply tells the message handling infra not
   * to free the message.
   *
   * Bounced message handlers MUST NOT block the data plane
   */
  am->message_bounce[VL_API_CONNECT_URI] = 1;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (uri_api_hookup);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
