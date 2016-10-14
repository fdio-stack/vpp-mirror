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
#include "uri.h"
#include <vlibmemory/api.h>

/** @file
    URI handling, bind tables
*/

/* FIXME eventually these should be registered by underlying transports */

static u32 (*bind_session_fns[SESSION_TYPE_N_TYPES])
(uri_main_t *, u16) =
{
#define _(A,a) vnet_bind_##a##_uri,
  foreach_uri_session_type
#undef _
};

static u32 (*unbind_session_fns[SESSION_TYPE_N_TYPES])
(uri_main_t *, u16) =
{
#define _(A,a) vnet_unbind_##a##_uri,
  foreach_uri_session_type
#undef _
};

static u8 * (*format_stream_session[SESSION_TYPE_N_TYPES])
(u8 *s, va_list *args) =
{
#define _(A, a) format_stream_session_##a,
  foreach_uri_session_type
#undef _
};

uri_main_t uri_main;
stream_server_main_t stream_server_main;

/** Create a session, ping the server by callback */
stream_session_t *
v4_stream_session_create (stream_server_main_t *ssm,
                          stream_server_t * ss,
                          stream_session_type_t session_type,
                          clib_bihash_kv_16_8_t session_key,
                          u32 connection_index,
                          int my_thread_index)
{
  svm_fifo_t * server_rx_fifo, * server_tx_fifo;
  svm_fifo_segment_private_t * fifo_segment;
  stream_session_t * s;
  u32 pool_index;
  u32 fifo_segment_index;
  unix_shared_memory_queue_t * vpp_event_queue;

  /* $$$ better allocation policy? */
  ASSERT (vec_len(ss->segment_indices));
  fifo_segment_index = ss->segment_indices[vec_len(ss->segment_indices)-1];
  fifo_segment = svm_fifo_get_segment (fifo_segment_index);

  /* $$$ size policy */
  server_rx_fifo = svm_fifo_segment_alloc_fifo (fifo_segment, 8192);

  /* $$$ callback to map another segment */
  ASSERT(server_rx_fifo);

  server_tx_fifo = svm_fifo_segment_alloc_fifo (fifo_segment, 8192);

  ASSERT(server_tx_fifo);

  pool_get (ssm->sessions[my_thread_index], s);
  memset (s, 0, sizeof (*s));

  /* Initialize backpointers */
  pool_index = s - ssm->sessions[my_thread_index];
  server_rx_fifo->server_session_index = pool_index;
  server_rx_fifo->server_thread_index = my_thread_index;

  server_tx_fifo->server_session_index = pool_index;
  server_tx_fifo->server_thread_index = my_thread_index;

  s->server_rx_fifo = server_rx_fifo;
  s->server_tx_fifo = server_tx_fifo;

  /* Initialize state machine, such as it is... */
  s->session_type = session_type;
  s->session_state = SESSION_STATE_CONNECTING;
  s->server_index = ss - ssm->servers;
  s->server_segment_index = fifo_segment_index;
  s->session_thread_index = my_thread_index;
  s->session_index = pool_index;
  s->transport_connection_index = connection_index;

  session_key.value = (((u64) my_thread_index) << 32) | (u64) pool_index;
  s->session_key = session_key;

  /* Add to the main lookup table */
  clib_bihash_add_del_16_8 (&ssm->v4_session_hash, &session_key,
                            1 /* is_add */);

  vpp_event_queue = ssm->vpp_event_queues[my_thread_index];

  /* Shoulder-tap the registered server */
  ss->session_create_callback (ss, s, vpp_event_queue);
  return (s);
}

void
v4_stream_session_delete (stream_server_main_t *ssm, stream_session_t * s)
{
  int rv;
  svm_fifo_segment_private_t * fifo_segment;
  u32 my_thread_index = ssm->vlib_main->cpu_index;

  /* delete from the main lookup table */
  rv = clib_bihash_add_del_16_8 (&ssm->v4_session_hash, &s->session_key,
                                 0 /* is_add */);

  if (rv)
    clib_warning ("hash delete error, rv %d", rv);

  /* recover the fifo segment */
  fifo_segment = svm_fifo_get_segment (s->server_segment_index);

  svm_fifo_segment_free_fifo (fifo_segment, s->server_rx_fifo);
  svm_fifo_segment_free_fifo (fifo_segment, s->server_tx_fifo);

  pool_put (ssm->sessions[my_thread_index], s);
}

/** Create a session, ping the server by callback */
stream_session_t *
v6_stream_session_create (stream_server_main_t *ssm,
                          stream_server_t * ss,
                          stream_session_type_t session_type,
                          clib_bihash_kv_48_8_t session_key,
                          u32 connection_index,
                          int my_thread_index)
{
  clib_warning("unimplemented");
  return 0;
}

/* types: fifo, tcp4, udp4, tcp6, udp6 */

u8 *
format_bind_table_entry (u8 * s, va_list * args)
{
  uri_bind_table_entry_t * e = va_arg (*args, uri_bind_table_entry_t *);
  int verbose = va_arg (*args, int);

  if (e == 0)
    {
      if (verbose)
        s = format (s, "%-15s%-15s%-20s%-10s%-10s",
                    "URI", "Server", "Segment", "API Client", "Cookie");
      else
        s = format (s, "%-15s%-15s",
                    "URI", "Server");
      return s;
    }

  if (verbose)
    s = format (s, "%-15s%-15s%-20s%-10d%-10d",
                e->bind_name, e->server_name, e->segment_name,
                e->bind_client_index,
                e->accept_cookie);
  else
    s = format (s, "%-15s%-15s", e->bind_name, e->server_name);
  return s;
}

/**** fifo uri */

u32
vnet_bind_fifo_uri (uri_main_t *um, u16 port)
{
  return 0;
}

u32
vnet_unbind_fifo_uri (uri_main_t *um, u16 port)
{
  return 0;
}

int vnet_connect_fifo_uri (char *uri, u32 api_client_index,
                           u64 * options, char *segment_name_arg, 
                           u32 * segment_name_length)
{
  uri_main_t * um = &uri_main;
  uri_bind_table_entry_t * e;
  uword * p;

  ASSERT(segment_name_length);

  p = hash_get_mem (um->uri_bind_table_entry_by_name, uri);

  if (!p)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  e = pool_elt_at_index (um->fifo_bind_table, p[0]);

  *segment_name_length = vec_len(e->segment_name);
  memcpy (segment_name_arg, e->segment_name, *segment_name_length);
  e->connect_client_index = api_client_index;

  return 0;
}

/**** end fifo URI */

int
port_decode (char *uri, u16 *port)
{
  char * cp;
  u32 port_number_host_byte_order;

  /* "udp4:12345" */
  cp = &uri[5];
  if (*cp == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  port_number_host_byte_order = 0;
  while (*cp != 0 && (*cp >= '0' && *cp <= '9'))
    {
      port_number_host_byte_order = (port_number_host_byte_order<<3) +
        (port_number_host_byte_order<<1);
      port_number_host_byte_order += *cp - '0';
      cp++;
    }

  if (port_number_host_byte_order > 65535)
    return VNET_API_ERROR_INVALID_VALUE;

  port[0] = port_number_host_byte_order;
  return 0;
}

int
uri_decode (char *uri, stream_session_type_t *sst, u16 *port)
{
  int rv;
  port[0] = ~0;

  /* Mumble top-level decode mumble */
  if (uri[0] == 'f')
    {
      sst[0] = SESSION_TYPE_FIFO;
    }
  else if (uri[0] == 'u' && uri[3] == '4')
    sst[0] = SESSION_TYPE_IP4_UDP;
  else if (uri[0] == 't' && uri[3] == '4')
    sst[0] = SESSION_TYPE_IP4_TCP;
  else
    return VNET_API_ERROR_UNKNOWN_URI_TYPE;

  if (sst[0] < SESSION_TYPE_FIFO)
    {
      if ((rv = port_decode (uri, port)))
        return rv;
    }

  return 0;
}

int vnet_bind_uri (vnet_bind_uri_args_t *a)
{
  uword * p;
  uri_main_t * um = &uri_main;
  api_main_t *am = &api_main;
  u32 my_thread_index = um->vlib_main->cpu_index;
  vl_api_registration_t *regp;
  u8 * segment_name;
  u8 * server_name;
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  stream_server_main_t * ssm = &stream_server_main;
  stream_server_t * ss;
  void * oldheap;
  int rv;
  uri_bind_table_entry_t * e;
  u16 * n, port_number_host_byte_order;
  stream_session_type_t sst = SESSION_TYPE_N_TYPES;

  ASSERT(a->uri);
  ASSERT(a->segment_name_length);

  p = hash_get_mem (um->uri_bind_table_entry_by_name, a->uri);

  if (p)
    return VNET_API_ERROR_ADDRESS_IN_USE;

  if ((rv = uri_decode (a->uri, &sst, &port_number_host_byte_order)))
    return rv;

  /* External client? */
  if (a->api_client_index != ~0)
    {
      regp = vl_api_client_index_to_registration (a->api_client_index);
      ASSERT(regp);
      server_name = format (0, "%s%c", regp->name, 0);
    }
  else
    server_name = format (0, "<internal>%c", 0);

  /*
   * $$$$ lookup client by api client index, to see if we're already
   * talking to this client about some other port
   */

  /* Unique segment name, per vpp instance */
  segment_name = format (0, "%d-%s%c", getpid(), a->uri, 0);
  ASSERT (vec_len(segment_name) <= 128);
  a->segment_name_length = vec_len(segment_name);
  memcpy (a->segment_name, segment_name, a->segment_name_length);

  if (sst != SESSION_TYPE_FIFO)
    {
      ca->segment_name = (char *) segment_name;
      ca->segment_size = a->segment_size;

      rv = svm_fifo_segment_create (ca);
      if (rv)
        {
          clib_warning("sm_fifo_segment_create ('%s', %d) failed",
                       a->segment_name, a->segment_size);
          return VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
        }

      pool_get(ssm->servers, ss);
      memset(ss, 0, sizeof(*ss));

      /* Allocate event fifo in the /vpe-api shared-memory segment */
      oldheap = svm_push_data_heap (am->vlib_rp);

      /* Allocate vpp event queue (once) */
      if (ssm->vpp_event_queues[my_thread_index] == 0)
        {
          ssm->vpp_event_queues[my_thread_index] =
              unix_shared_memory_queue_init (
                  2048 /* nels $$$$ config */, sizeof(fifo_event_t),
                  0 /* consumer pid */,
                  0 /* (do not) send signal when queue non-empty */);
        }

      /* Allocate server event queue */
      if (ss->event_queue == 0)
        {
          ss->event_queue = unix_shared_memory_queue_init (
              128 /* nels $$$$ config */, sizeof(fifo_event_t),
              0 /* consumer pid */,
              0 /* (do not) send signal when queue non-empty */);
        }
      svm_pop_heap (oldheap);

      a->server_event_queue_address = (u64) ss->event_queue;

      ss->session_create_callback = a->send_session_create_callback;
      ss->session_delete_callback = v4_stream_session_delete;
      ss->session_clear_callback = a->send_session_clear_callback;
      ss->builtin_server_rx_callback = a->builtin_server_rx_callback;
      ss->api_client_index = a->api_client_index;

      vec_add1(ss->segment_indices, ca->new_segment_index);

      n = sparse_vec_validate(
          ssm->stream_server_by_dst_port[sst],
          clib_host_to_net_u16 (port_number_host_byte_order));
      n[0] = (ss - ssm->servers) + 1; /* avoid SPARSE_VEC_INDEX_INVALID */

      bind_session_fns[sst] (um, port_number_host_byte_order);
    }

  pool_get (um->fifo_bind_table, e);
  memset (e, 0, sizeof (*e));

  e->bind_name = format (0, "%s%c", a->uri, 0);
  e->server_name = server_name;
  e->segment_name = segment_name;
  e->bind_client_index = a->api_client_index;
  e->accept_cookie = a->accept_cookie;

  hash_set_mem (um->uri_bind_table_entry_by_name, e->bind_name,
                e - um->fifo_bind_table);

  return 0;
}

int vnet_unbind_uri (char * uri, u32 api_client_index)
{
  uri_main_t * um = &uri_main;
  api_main_t *am = &api_main;
  stream_server_main_t * ssm = &stream_server_main;
  stream_server_t * ss;
  vl_api_registration_t *regp;
  uword * p;
  void * oldheap;
  u16 * n, port_number_host_byte_order;
  int i, j, rv;
  u32 * deleted_sessions = 0;
  u32 * deleted_thread_indices = 0;
  stream_session_type_t sst = SESSION_TYPE_N_TYPES;

  ASSERT(uri);

  p = hash_get_mem (um->uri_bind_table_entry_by_name, uri);

  if (!p)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  if ((rv = uri_decode (uri, &sst, &port_number_host_byte_order)))
    return rv;

  /* External client? */
  if (api_client_index != ~0)
    {
      regp = vl_api_client_index_to_registration (api_client_index);
      ASSERT(regp);
    }

  if (sst != SESSION_TYPE_FIFO)
    {
      /* Turn off the uri-queue mapping */
      n = sparse_vec_validate(
          ssm->stream_server_by_dst_port[sst],
          clib_host_to_net_u16 (port_number_host_byte_order));
      n[0] = SPARSE_VEC_INVALID_INDEX;
    }

  unbind_session_fns[sst] (um, port_number_host_byte_order);

  /*
   * Find the stream_server_t corresponding to the api client
   * $$$$ maybe add a hash table? There may only be three or four...
   */
  pool_foreach (ss, ssm->servers,
  ({
    if (ss->api_client_index == api_client_index)
      goto found;
  }));

  /* Better never happen... */
  return VNET_API_ERROR_INVALID_VALUE_2;

 found:

  /* Across all fifo segments used by the server */
  for (j = 0; j < vec_len (ss->segment_indices); j++)
    {
      svm_fifo_segment_private_t * fifo_segment;
      svm_fifo_t ** fifos;
      /* Vector of fifos allocated in the segment */
      fifo_segment = svm_fifo_get_segment (ss->segment_indices[j]);
      fifos = (svm_fifo_t **) fifo_segment->h->fifos;

      /*
       * Remove any residual sessions from the session lookup table
       * Don't bother deleting the individual fifos, we're going to
       * throw away the fifo segment in a minute.
       */
      for (i = 0; i < vec_len(fifos); i++)
        {
          svm_fifo_t * fifo;
          u32 session_index, thread_index;
          stream_session_t * session;

          fifo = fifos[i];
          session_index = fifo->server_session_index;
          thread_index = fifo->server_thread_index;

          session = pool_elt_at_index (ssm->sessions[thread_index],
                                       session_index);

          /* Add to the deleted_sessions vector (once!) */
          if (!session->is_deleted)
            {
              session->is_deleted = 1;
              vec_add1(deleted_sessions,
                       session - ssm->sessions[thread_index]);
              vec_add1 (deleted_thread_indices, thread_index);
            }

          clib_bihash_add_del_16_8 (&ssm->v4_session_hash, &session->session_key,
                                    0 /* is_add */);
      }

      for (i = 0; i < vec_len (deleted_sessions); i++)
        pool_put_index (ssm->sessions[deleted_thread_indices[i]],
                        deleted_sessions[i]);

      vec_reset_length (deleted_sessions);
      vec_reset_length (deleted_thread_indices);

      svm_fifo_segment_delete (fifo_segment);
    }

  vec_free (deleted_sessions);
  vec_free (deleted_thread_indices);

  /* Free the event fifo in the /vpe-api shared-memory segment */
  oldheap = svm_push_data_heap (am->vlib_rp);

  if (ss->event_queue)
    unix_shared_memory_queue_free (ss->event_queue);

  svm_pop_heap (oldheap);

  /* Clean out the uri->server name mapping */
  hash_unset_mem (um->uri_bind_table_entry_by_name, uri);
  pool_put_index (um->fifo_bind_table, p[0]);

  pool_put (ssm->servers, ss);

  return 0;
}

int vnet_connect_uri (char * uri, u32 api_client_index,
                      u64 *options, char *segment_name, u32 *name_length)
{
  ASSERT(uri);

  /* Mumble top-level decode mumble */
  if (uri[0] == 'f')
    return vnet_connect_fifo_uri (uri, api_client_index, options, 
                                  segment_name, name_length);
  else
    return VNET_API_ERROR_UNKNOWN_URI_TYPE;
}

int vnet_disconnect_uri_session (u32 client_index, u32 session_index,
                                 u32 thread_index)
{
  stream_server_main_t * ssm = &stream_server_main;
  stream_session_t * session;
  stream_session_t * pool;

  if (thread_index >= vec_len (ssm->sessions))
    return VNET_API_ERROR_INVALID_VALUE;

  pool = ssm->sessions[thread_index];

  if (pool_is_free_index (pool, session_index))
    return VNET_API_ERROR_INVALID_VALUE_2;

  session = pool_elt_at_index (ssm->sessions[thread_index],
                               session_index);

  switch (session->session_type)
    {
    case SESSION_TYPE_IP4_UDP:
      v4_stream_session_delete (ssm, session);
      break;

    default:
      return VNET_API_ERROR_UNIMPLEMENTED;
    }
  return 0;
}

static clib_error_t *
show_uri_command_fn (vlib_main_t * vm,
                     unformat_input_t * input,
                     vlib_cli_command_t * cmd)
{
  uri_main_t *um = &uri_main;
  stream_server_main_t * ssm = &stream_server_main;
  uri_bind_table_entry_t * e;
  int do_server = 0;
  int do_session = 0;
  int verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "server"))
        do_server = 1;
      else if (unformat (input, "session"))
        do_session = 1;
      else if (unformat (input, "verbose"))
        verbose = 1;
      else if (unformat (input, "detail"))
        verbose = 2;
      else
        break;
    }

  if (do_server)
    {
      if (pool_elts (um->fifo_bind_table))
        {
          vlib_cli_output (vm, "%U", format_bind_table_entry, 0 /* header */,
                           verbose);
          /* *INDENT-OFF* */
          pool_foreach (e, um->fifo_bind_table,
          ({
            vlib_cli_output (vm, "%U", format_bind_table_entry, e, verbose);
          }));
          /* *INDENT-OFF* */
        }
      else
        vlib_cli_output (vm, "No active server bindings");
    }

  if (do_session)
    {
      int i;
      stream_session_t * pool;
      stream_session_t * s;
      u8 * str;

      for (i = 0; i < vec_len (ssm->sessions); i++)
        {
          pool = ssm->sessions[i];

          if (pool_elts (pool))
            {

              vlib_cli_output (vm, "Thread %d: %d active sessions",
                               i, pool_elts (pool));
              if (verbose)
                {
                  str = format (0, "%-20s%-20s%-10s%-10s%-8s%-20s%-20s%-8s%-8s",
                                "Src", "Dst", "SrcP", "DstP", "Proto",
                                "Rx fifo", "Tx fifo", "Thread", "Index");

                  /* *INDENT-OFF* */
                  pool_foreach (s, pool,
                  ({
                    str = format (0, "%-20llx%-20llx%-6d%-6d",
                                s->server_rx_fifo, s->server_tx_fifo, i,
                                s - pool);
                    vlib_cli_output (vm, "%U%s",
                                     format_stream_session[s->session_type],
                                     &s->transport_connection_index,
                                     &s->session_thread_index, str);
                  }));
                  /* *INDENT-OFF* */
                }
            }
          else
            vlib_cli_output (vm, "Thread %d: no active sessions", i);
        }
    }

  return 0;
}

VLIB_CLI_COMMAND (show_uri_command, static) = {
    .path = "show uri",
    .short_help = "show uri [server|session] [verbose]",
    .function = show_uri_command_fn,
};


static clib_error_t *
clear_uri_session_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  stream_server_main_t * ssm = &stream_server_main;
  u32 thread_index = 0;
  u32 session_index = ~0;
  stream_session_t * pool, * session;
  stream_server_t * server;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "thread %d", &thread_index))
        ;
      else if (unformat (input, "session %d", &session_index))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }

  if (session_index == ~0)
    return clib_error_return (0, "session <nn> required, but not set.");

  if (thread_index > vec_len(ssm->sessions))
    return clib_error_return (0, "thread %d out of range [0-%d]",
                              thread_index, vec_len(ssm->sessions));

  pool = ssm->sessions[thread_index];

  if (pool_is_free_index (pool, session_index))
    return clib_error_return (0, "session %d not active", session_index);

  session = pool_elt_at_index (pool, session_index);

  server = pool_elt_at_index (ssm->servers, session->server_index);

  server->session_clear_callback (ssm, server, session);

  return 0;
}

VLIB_CLI_COMMAND (clear_uri_session_command, static) = {
    .path = "clear uri session",
    .short_help = "clear uri session",
    .function = clear_uri_session_command_fn,
};

static clib_error_t *
uri_init (vlib_main_t * vm)
{
  uri_main_t * um = &uri_main;

  um->uri_bind_table_entry_by_name = hash_create_string (0, sizeof (uword));
  um->vlib_main = vm;
  um->vnet_main = vnet_get_main();
  return 0;
}

VLIB_INIT_FUNCTION (uri_init);

static clib_error_t * 
stream_server_init (vlib_main_t * vm)
{
  u32 num_threads;
  vlib_thread_main_t *tm = &vlib_thread_main;
  stream_server_main_t * ssm = &stream_server_main;
  int i;

  num_threads = 1 /* main thread */ + tm->n_eal_threads;

  if (num_threads < 1)
    return clib_error_return (0, "n_thread_stacks not set");

  
  /* $$$ config parameters */
  svm_fifo_segment_init(0x200000000ULL /* first segment base VA */, 
                        20 /* timeout in seconds */);

  /* configure per-thread ** vectors */
  vec_validate (ssm->sessions, num_threads - 1);
  vec_validate (ssm->session_indices_to_enqueue_by_thread, num_threads-1);
  vec_validate (ssm->tx_buffers, num_threads - 1);
  vec_validate (ssm->fifo_events, num_threads - 1);
  vec_validate (ssm->current_enqueue_epoch, num_threads - 1);
  vec_validate (ssm->vpp_event_queues, num_threads - 1);
  vec_validate (ssm->copy_buffers, num_threads - 1);

  /** FIXME move to udp main*/
  vec_validate (udp4_sessions, num_threads - 1);


  /* $$$$ preallocate hack config parameter */
  for (i = 0; i < 200000; i++)
    {
      stream_session_t * ss;
      pool_get (ssm->sessions[0], ss);
      memset (ss, 0, sizeof (*ss));
    }

  for (i = 0; i < 200000; i++)
      pool_put_index (ssm->sessions[0], i);

  clib_bihash_init_16_8 (&ssm->v4_session_hash, "v4 session table",
                         200000 /* $$$$ config parameter nbuckets */,
                         (64<<20) /*$$$ config parameter table size */);
  
  ssm->vlib_main = vm;
  ssm->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (stream_server_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
