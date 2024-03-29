/*
 *------------------------------------------------------------------
 * af_packet.c - linux kernel packet interface
 *
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
 *------------------------------------------------------------------
 */

#include <linux/if_packet.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <vnet/devices/af_packet/af_packet.h>

#define foreach_af_packet_input_error

typedef enum
{
#define _(f,s) AF_PACKET_INPUT_ERROR_##f,
  foreach_af_packet_input_error
#undef _
    AF_PACKET_INPUT_N_ERROR,
} af_packet_input_error_t;

static char *af_packet_input_error_strings[] = {
#define _(n,s) s,
  foreach_af_packet_input_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  int block;
  struct tpacket2_hdr tph;
} af_packet_input_trace_t;

static u8 *
format_af_packet_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  af_packet_input_trace_t *t = va_arg (*args, af_packet_input_trace_t *);
  uword indent = format_get_indent (s);

  s = format (s, "af_packet: hw_if_index %d next-index %d",
	      t->hw_if_index, t->next_index);

  s =
    format (s,
	    "\n%Utpacket2_hdr:\n%Ustatus 0x%x len %u snaplen %u mac %u net %u"
	    "\n%Usec 0x%x nsec 0x%x vlan %U"
#ifdef TP_STATUS_VLAN_TPID_VALID
	    " vlan_tpid %u"
#endif
	    ,
	    format_white_space, indent + 2,
	    format_white_space, indent + 4,
	    t->tph.tp_status,
	    t->tph.tp_len,
	    t->tph.tp_snaplen,
	    t->tph.tp_mac,
	    t->tph.tp_net,
	    format_white_space, indent + 4,
	    t->tph.tp_sec,
	    t->tph.tp_nsec, format_ethernet_vlan_tci, t->tph.tp_vlan_tci
#ifdef TP_STATUS_VLAN_TPID_VALID
	    , t->tph.tp_vlan_tpid
#endif
    );
  return s;
}

always_inline void
buffer_add_to_chain (vlib_main_t * vm, u32 bi, u32 first_bi, u32 prev_bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_buffer_t *first_b = vlib_get_buffer (vm, first_bi);
  vlib_buffer_t *prev_b = vlib_get_buffer (vm, prev_bi);

  /* update first buffer */
  first_b->total_length_not_including_first_buffer += b->current_length;

  /* update previous buffer */
  prev_b->next_buffer = bi;
  prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

  /* update current buffer */
  b->next_buffer = 0;
}

always_inline uword
af_packet_device_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame, af_packet_if_t * apif)
{
  af_packet_main_t *apm = &af_packet_main;
  struct tpacket2_hdr *tph;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 block = 0;
  u32 rx_frame;
  u32 n_free_bufs;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 block_size = apif->rx_req->tp_block_size;
  u32 frame_size = apif->rx_req->tp_frame_size;
  u32 frame_num = apif->rx_req->tp_frame_nr;
  u8 *block_start = apif->rx_ring + block * block_size;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 cpu_index = os_get_cpu_number ();
  u32 n_buffer_bytes = vlib_buffer_free_list_buffer_size (vm,
							  VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  u32 min_bufs = apif->rx_req->tp_frame_size / n_buffer_bytes;

  if (apif->per_interface_next_index != ~0)
    next_index = apif->per_interface_next_index;

  n_free_bufs = vec_len (apm->rx_buffers[cpu_index]);
  if (PREDICT_FALSE (n_free_bufs < VLIB_FRAME_SIZE))
    {
      vec_validate (apm->rx_buffers[cpu_index],
		    VLIB_FRAME_SIZE + n_free_bufs - 1);
      n_free_bufs +=
	vlib_buffer_alloc (vm, &apm->rx_buffers[cpu_index][n_free_bufs],
			   VLIB_FRAME_SIZE);
      _vec_len (apm->rx_buffers[cpu_index]) = n_free_bufs;
    }

  rx_frame = apif->next_rx_frame;
  tph = (struct tpacket2_hdr *) (block_start + rx_frame * frame_size);
  while ((tph->tp_status & TP_STATUS_USER) && (n_free_bufs > min_bufs))
    {
      vlib_buffer_t *b0 = 0, *first_b0 = 0;
      u32 next0 = next_index;

      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while ((tph->tp_status & TP_STATUS_USER) && (n_free_bufs > min_bufs) &&
	     n_left_to_next)
	{
	  u32 data_len = tph->tp_snaplen;
	  u32 offset = 0;
	  u32 bi0 = 0, first_bi0 = 0, prev_bi0;

	  while (data_len)
	    {
	      /* grab free buffer */
	      u32 last_empty_buffer =
		vec_len (apm->rx_buffers[cpu_index]) - 1;
	      prev_bi0 = bi0;
	      bi0 = apm->rx_buffers[cpu_index][last_empty_buffer];
	      b0 = vlib_get_buffer (vm, bi0);
	      _vec_len (apm->rx_buffers[cpu_index]) = last_empty_buffer;
	      n_free_bufs--;

	      /* copy data */
	      u32 bytes_to_copy =
		data_len > n_buffer_bytes ? n_buffer_bytes : data_len;
	      b0->current_data = 0;
	      clib_memcpy (vlib_buffer_get_current (b0),
			   (u8 *) tph + tph->tp_mac + offset, bytes_to_copy);

	      /* fill buffer header */
	      b0->current_length = bytes_to_copy;

	      if (offset == 0)
		{
		  b0->total_length_not_including_first_buffer = 0;
		  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] = apif->sw_if_index;
		  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  first_bi0 = bi0;
		  first_b0 = vlib_get_buffer (vm, first_bi0);
		}
	      else
		buffer_add_to_chain (vm, bi0, first_bi0, prev_bi0);

	      offset += bytes_to_copy;
	      data_len -= bytes_to_copy;
	    }
	  n_rx_packets++;
	  n_rx_bytes += tph->tp_snaplen;
	  to_next[0] = first_bi0;
	  to_next += 1;
	  n_left_to_next--;

	  /* trace */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (first_b0);
	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      af_packet_input_trace_t *tr;
	      vlib_trace_buffer (vm, node, next0, first_b0,	/* follow_chain */
				 0);
	      vlib_set_trace_count (vm, node, --n_trace);
	      tr = vlib_add_trace (vm, node, first_b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->hw_if_index = apif->hw_if_index;
	      clib_memcpy (&tr->tph, tph, sizeof (struct tpacket2_hdr));
	    }

	  /* redirect if feature path enabled */
	  vnet_feature_start_device_input_x1 (apif->sw_if_index, &next0, b0,
					      0);

	  /* enque and take next packet */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, first_bi0, next0);

	  /* next packet */
	  tph->tp_status = TP_STATUS_KERNEL;
	  rx_frame = (rx_frame + 1) % frame_num;
	  tph = (struct tpacket2_hdr *) (block_start + rx_frame * frame_size);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  apif->next_rx_frame = rx_frame;

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     os_get_cpu_number (), apif->hw_if_index, n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (cpu_index, n_rx_packets);
  return n_rx_packets;
}

static uword
af_packet_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{
  int i;
  u32 n_rx_packets = 0;
  u32 cpu_index = os_get_cpu_number ();
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif;

  for (i = 0; i < vec_len (apm->interfaces); i++)
    {
      apif = vec_elt_at_index (apm->interfaces, i);
      if (apif->is_admin_up &&
	  (i % apm->input_cpu_count) ==
	  (cpu_index - apm->input_cpu_first_index))
	n_rx_packets += af_packet_device_input_fn (vm, node, frame, apif);
    }

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (af_packet_input_node) = {
  .function = af_packet_input_fn,
  .name = "af-packet-input",
  .sibling_of = "device-input",
  .format_trace = format_af_packet_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  /**
   * default state is INTERRUPT mode, switch to POLLING if worker threads are enabled
   */
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = AF_PACKET_INPUT_N_ERROR,
  .error_strings = af_packet_input_error_strings,
};

VLIB_NODE_FUNCTION_MULTIARCH (af_packet_input_node, af_packet_input_fn)
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
