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
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/feature/feature.h>

typedef struct {
  u32 next_index;
} syn_filter4_trace_t;

/* packet trace format function */
static u8 * format_syn_filter4_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  syn_filter4_trace_t * t = va_arg (*args, syn_filter4_trace_t *);
  
  s = format (s, "SYN_FILTER4: next index %d\n",
              t->next_index);
  return s;
}

static vlib_node_registration_t syn_filter4_node;

#define foreach_syn_filter_error                \
_(DROPPED, "TCP SYN packets dropped")           \
_(PROCESSED, "Packets processed")

typedef enum {
#define _(sym,str) SYN_FILTER_ERROR_##sym,
  foreach_syn_filter_error
#undef _
  SYN_FILTER_N_ERROR,
} syn_filter_error_t;

static char * syn_filter4_error_strings[] = {
#define _(sym,string) string,
  foreach_syn_filter_error
#undef _
};

typedef enum {
  SYN_FILTER_NEXT_DROP,
  SYN_FILTER_N_NEXT,
} syn_filter_next_t;

extern vnet_feature_arc_registration_t vnet_feat_arc_ip4_local;

static uword
syn_filter4_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  syn_filter_next_t next_index;
  u32 pkts_processed = 0;
  u32 pkts_dropped = 0;
  vnet_feature_main_t *fm = &feature_main;
  u8 arc_index = vnet_feat_arc_ip4_local.feature_arc_index;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

#if 0
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          u8 tmp0[6], tmp1[6];
          ethernet_header_t *en0, *en1;
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;
            
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
            
	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

          /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          ASSERT (b0->current_data == 0);
          ASSERT (b1->current_data == 0);
          
          en0 = vlib_buffer_get_current (b0);
          en1 = vlib_buffer_get_current (b1);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          /* Send pkt back out the RX interface */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_if_index0;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = sw_if_index1;

          pkts_swapped += 2;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    syn_filter4_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->next_index = next0;
                    clib_memcpy (t->new_src_mac, en0->src_address,
                                 sizeof (t->new_src_mac));
                    clib_memcpy (t->new_dst_mac, en0->dst_address,
                                 sizeof (t->new_dst_mac));
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    syn_filter4_trace_t *t = 
                      vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->next_index = next1;
                    clib_memcpy (t->new_src_mac, en1->src_address,
                                 sizeof (t->new_src_mac));
                    clib_memcpy (t->new_dst_mac, en1->dst_address,
                                 sizeof (t->new_dst_mac));
                  }
              }
            
            /* verify speculative enqueues, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, bi1, next0, next1);
        }
#endif 

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          vnet_get_config_data
              (&cm->config_main, &b0->current_config_index,
               &next0, 0 /* sizeof (c0[0]) */);

          /* $$$ syn filter right here */

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
          {
              syn_filter4_trace_t *t = 
                  vlib_add_trace (vm, node, b0, sizeof (*t));
              t->next_index = next0;
          }
            
          pkts_processed += 1;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, syn_filter4_node.index, 
                               SYN_FILTER_ERROR_PROCESSED, pkts_processed);
  vlib_node_increment_counter (vm, syn_filter4_node.index, 
                               SYN_FILTER_ERROR_DROPPED, pkts_dropped);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (syn_filter4_node, static) = {
  .function = syn_filter4_node_fn,
  .name = "syn-filter-4",
  .vector_size = sizeof (u32),
  .format_trace = format_syn_filter4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(syn_filter4_error_strings),
  .error_strings = syn_filter4_error_strings,

  .n_next_nodes = SYN_FILTER_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SYN_FILTER_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (syn_filter_4, static) = {
  .arc_name = "ip4-local",
  .node_name = "syn-filter-4",
  .runs_before = VNET_FEATURES("ip4-local-end-of-arc"), 
};

int syn_filter_enable_disable (u32 sw_if_index, int enable_disable)
{
  vnet_main_t * vnm = vnet_get_main();
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (vnm->interface_main.sw_interfaces, 
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (vnm, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  
  rv = vnet_feature_enable_disable ("ip4-local", "syn-filter-4",
                                    sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
syn_filter_enable_disable_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main();
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else if (unformat (input, "%U", unformat_vnet_sw_interface,
                       vnm, &sw_if_index))
      ;
    else
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");
    
  rv = syn_filter_enable_disable (sw_if_index, enable_disable);

  switch(rv) {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return 
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  case VNET_API_ERROR_INVALID_VALUE:
    return clib_error_return (0, "feature arc not found");

  case VNET_API_ERROR_INVALID_VALUE_2:
    return clib_error_return (0, "feature node not found");

  default:
    return clib_error_return (0, "syn_filter_enable_disable returned %d", rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (sr_content_command, static) = {
    .path = "ip syn filter",
    .short_help = 
    "ip syn filter <interface-name> [disable]",
    .function = syn_filter_enable_disable_command_fn,
};
