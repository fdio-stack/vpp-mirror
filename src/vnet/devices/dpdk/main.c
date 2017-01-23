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

#include <vnet/vnet.h>
#include <vnet/devices/dpdk/dpdk.h>


/*
 * Called by the dpdk driver's rte_delay_us() function.
 * Return 0 to have the dpdk do a regular delay loop.
 * Return 1 if to skip the delay loop because we are suspending
 * the calling vlib process instead.
 */
int
rte_delay_us_override (unsigned us)
{
  vlib_main_t *vm;

  /* Don't bother intercepting for short delays */
  if (us < 10)
    return 0;

  /*
   * Only intercept if we are in a vlib process.
   * If we are called from a vlib worker thread or the vlib main
   * thread then do not intercept. (Must not be called from an
   * independent pthread).
   */
  if (os_get_cpu_number () == 0)
    {
      /*
       * We're in the vlib main thread or a vlib process. Make sure
       * the process is running and we're not still initializing.
       */
      vm = vlib_get_main ();
      if (vlib_in_process_context (vm))
	{
	  /* Only suspend for the admin_down_process */
	  vlib_process_t *proc = vlib_get_current_process (vm);
	  if (!(proc->flags & VLIB_PROCESS_IS_RUNNING) ||
	      (proc->node_runtime.function != admin_up_down_process))
	    return 0;

	  f64 delay = 1e-6 * us;
	  vlib_process_suspend (vm, delay);
	  return 1;
	}
    }
  return 0;			// no override
}

#if RTE_VERSION >= RTE_VERSION_NUM(16, 11, 0, 0)
static void
rte_delay_us_override_cb (unsigned us)
{
  if (rte_delay_us_override (us) == 0)
    rte_delay_us_block (us);
}
#endif

static clib_error_t * dpdk_main_init (vlib_main_t * vm)
{
  clib_error_t * error = 0;

  if ((error = vlib_call_init_function (vm, dpdk_init)))
    return error;

#if DPDK
#if RTE_VERSION >= RTE_VERSION_NUM(16, 11, 0, 0)
  /* register custom delay function */
  rte_delay_us_callback_register (rte_delay_us_override_cb);
#endif
#endif
  return error;
}

VLIB_INIT_FUNCTION (dpdk_main_init);

