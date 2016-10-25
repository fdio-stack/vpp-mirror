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

#ifndef included_tcp_packet_h
#define included_tcp_packet_h

#include <vnet/vnet.h>

/* TCP flags bit 0 first. */
#define foreach_tcp_flag                        \
  _ (FIN)                                       \
  _ (SYN)                                       \
  _ (RST)                                       \
  _ (PSH)                                       \
  _ (ACK)                                       \
  _ (URG)                                       \
  _ (ECE)                                       \
  _ (CWR)

enum
{
#define _(f) TCP_FLAG_BIT_##f,
  foreach_tcp_flag
#undef _
  TCP_N_FLAG_BITS,
};

enum
{
#define _(f) TCP_FLAG_##f = 1 << TCP_FLAG_BIT_##f,
  foreach_tcp_flag
#undef _
};

typedef struct _tcp_header
{
  union
  {
    struct
    {
      u16 src_port; /**< Source port. */
      u16 dst_port; /**< Destination port. */
    };
    struct
    {
      u16 src, dst;
    };
  };

  u32 seq_number;       /**< Sequence number of the first data octet in this
                         *   segment, except when SYN is present. If SYN
                         *   is present the seq number is is the ISN and the
                         *   first data octet is ISN+1 */
  u32 ack_number;       /**< Acknowledgement number if ACK is set. It contains
                         *   the value of the next sequence number the sender
                         *   of the segment is expecting to receive. */

  union
  {
    u16 reserved1:4,    /**< Reserved. */
        data_offset:4,  /**< Number of 32bit words in TCP header. */
        fin:1,          /**< No more data from sender. */
        syn:1,          /**< Synchronize sequence numbers. */
        rst:1,          /**< Reset the connection. */
        psh:1,          /**< Push function. */
        ack:1,          /**< Ack field significant. */
        urg:1,          /**< Urgent pointer field significant. */
        ece:1,          /**< ECN-echo. Receiver got CE packet */
        cwr:1;          /**< Sender reduced congestion window */
    struct
    {
      u8 data_offset_and_reserved;
      u8 flags;
    };
  };

  u16 window;           /**< Number of bytes sender is willing to receive. */
  u16 checksum;         /**< Checksum of TCP pseudo header and data. */
  u16 urgent_pointer;   /**< Seq number of the byte after the urgent data. */
} tcp_header_t;

always_inline int
tcp_header_bytes (tcp_header_t *t)
{
  return t->data_offset * sizeof(u32);
}

/* TCP options. */
typedef enum tcp_option_type
{
  TCP_OPTION_EOL = 0,                   /**< End of options. */
  TCP_OPTION_NOOP = 1,                  /**< No operation. */
  TCP_OPTION_MSS = 2,                   /**< Limit MSS. */
  TCP_OPTION_WINDOW_SCALE = 3,          /**< Window scale. */
  TCP_OPTION_SACK_PERMITTED = 4,        /**< Selective Ack permitted. */
  TCP_OPTION_SACK_BLOCK = 5,            /**< Selective Ack block. */
  TCP_OPTION_TIMESTAMP = 8,             /**< Timestamps. */
  TCP_OPTION_UTO = 28,                  /**< User timeout. */
  TCP_OPTION_AO = 29,                   /**< Authentication Option. */
} tcp_option_type_t;

/* TCP option lengths */
#define TCP_OPTION_LEN_EOL              1
#define TCP_OPTION_LEN_NOOP             1
#define TCP_OPTION_LEN_MSS              4
#define TCP_OPTION_LEN_WINDOW_SCALE     3
#define TCP_OPTION_LEN_SACK_PERMITTED   2
#define TCP_OPTION_LEN_TIMESTAMP        10

#define TCP_MAX_WND_SCALE               14

#endif /* included_tcp_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
