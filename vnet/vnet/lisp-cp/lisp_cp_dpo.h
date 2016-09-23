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

#ifndef __LISP_CP_DPO_H__
#define __LISP_CP_DPO_H__

#include <vnet/vnet.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/dpo.h>

/**
 * A representation of punt to the LISP control plane.
 */
typedef struct lisp_cp_dpo_t
{
    /**
     * The transport payload type.
     */
    fib_protocol_t lcd_proto;
} lisp_cp_dpo_t;

extern index_t lisp_cp_dpo_get(fib_protocol_t proto);

extern void lisp_cp_dpo_module_init(void);

#endif
