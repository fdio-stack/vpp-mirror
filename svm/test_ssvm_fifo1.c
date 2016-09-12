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

#include "ssvm_fifo_segment.h"


clib_error_t * 
test_ssvm_fifo (int verbose)
{
  svm_fifo_segment_create_args_t _a, *a = &_a;
  svm_fifo_segment_private_t * sp;
  svm_fifo_t * f;
  int rv;
  u8 * test_data;
  u8 * retrieved_data = 0;
  clib_error_t * error = 0;
  int pid = getpid();

  memset (a, 0, sizeof (*a));

  a->segment_name = "fifo-test1";
  a->segment_size = 256<<10;

  rv = svm_fifo_segment_create (a);

  if (rv)
    return clib_error_return (0, "svm_fifo_segment_create returned %d", rv);

  sp = a->rv;

  f = svm_fifo_segment_alloc_fifo (sp, 4096);

  if (f == 0)
    return clib_error_return (0, "svm_fifo_segment_alloc_fifo failed");

  test_data = format (0, "Hello world%c", 0);
  vec_validate (retrieved_data, vec_len(test_data)-1);
  
  while (svm_fifo_max_enqueue(f) >= vec_len (test_data))
    svm_fifo_enqueue (f, pid, vec_len (test_data), test_data);

  while (svm_fifo_max_dequeue(f) >= vec_len (test_data))
    svm_fifo_dequeue (f, pid, vec_len (retrieved_data), retrieved_data);

  while (svm_fifo_max_enqueue(f) >= vec_len (test_data))
    svm_fifo_enqueue (f, pid, vec_len (test_data), test_data);
  
  while (svm_fifo_max_dequeue(f) >= vec_len (test_data))
    svm_fifo_dequeue (f, pid, vec_len (retrieved_data), retrieved_data);
  
  if (!memcmp (retrieved_data, test_data, vec_len(test_data)))
    error = clib_error_return (0, "data test OK, got '%s'", retrieved_data);
  else
    error = clib_error_return (0, "data test FAIL!");

  svm_fifo_segment_free_fifo (sp, f);

  return error;
}


int test_ssvm_fifo1 (unformat_input_t * input)
{
  clib_error_t * error = 0;
  int verbose = 0;
  
  svm_fifo_segment_init();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
        ;
      else if (unformat(input, "verbose"))
        verbose = 1;
      else
	{
	  error = clib_error_create ("unknown input `%U'\n",
				     format_unformat_error, input);
          goto out;
	}
    }

  error = test_ssvm_fifo (verbose);

 out:
  if (error)
    clib_error_report (error);


  return 0;
}



int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int r;

  unformat_init_command_line (&i, argv);
  r = test_ssvm_fifo1 (&i);
  unformat_free (&i);
  return r;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

