/* packet-ceph.c
 * Routines for Ceph dissection
 * Copyright 2014, Kevin Cox <kevincox@kevincox.ca>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR ADD PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/to_str.h>

/* Forward declaration that is needed below if using the
 * proto_reg_handoff_ceph function as a callback for when protocol
 * preferences get changed. */
void proto_reg_handoff_ceph(void);
void proto_register_ceph(void);

static dissector_handle_t ceph_handle;

/* Initialize the protocol and registered fields */
static int proto_ceph                      = -1;
static int hf_node_id                      = -1;
static int hf_node_type                    = -1;
static int hf_node_nonce                   = -1;
static int hf_node_name                    = -1;
static int hf_version                      = -1;
static int hf_client_info                  = -1;
static int hf_server_info                  = -1;
static int hf_sockaddr                     = -1;
static int hf_inet_family                  = -1;
static int hf_port                         = -1;
static int hf_addr_ipv4                    = -1;
static int hf_addr_ipv6                    = -1;
static int hf_blob_data                    = -1;
static int hf_blob_size                    = -1;
static int hf_string_data                  = -1;
static int hf_string_size                  = -1;
static int hf_time                         = -1;
static int hf_time_sec                     = -1;
static int hf_time_nsec                    = -1;
static int hf_features                     = -1;
static int hf_features_high                = -1;
static int hf_features_low                 = -1;
static int hf_feature_uid                  = -1;
static int hf_feature_nosrcaddr            = -1;
static int hf_feature_monclockcheck        = -1;
static int hf_feature_flock                = -1;
static int hf_feature_subscribe2           = -1;
static int hf_feature_monnames             = -1;
static int hf_feature_reconnect_seq        = -1;
static int hf_feature_dirlayouthash        = -1;
static int hf_feature_objectlocator        = -1;
static int hf_feature_pgid64               = -1;
static int hf_feature_incsubosdmap         = -1;
static int hf_feature_pgpool3              = -1;
static int hf_feature_osdreplymux          = -1;
static int hf_feature_osdenc               = -1;
static int hf_feature_omap                 = -1;
static int hf_feature_monenc               = -1;
static int hf_feature_query_t              = -1;
static int hf_feature_indep_pg_map         = -1;
static int hf_feature_crush_tunables       = -1;
static int hf_feature_chunky_scrub         = -1;
static int hf_feature_mon_nullroute        = -1;
static int hf_feature_mon_gv               = -1;
static int hf_feature_backfill_reservation = -1;
static int hf_feature_msg_auth             = -1;
static int hf_feature_recovery_reservation = -1;
static int hf_feature_crush_tunables2      = -1;
static int hf_feature_createpoolid         = -1;
static int hf_feature_reply_create_inode   = -1;
static int hf_feature_osd_hbmsgs           = -1;
static int hf_feature_mdsenc               = -1;
static int hf_feature_osdhashpspool        = -1;
static int hf_feature_mon_single_paxos     = -1;
static int hf_feature_osd_snapmapper       = -1;
static int hf_feature_mon_scrub            = -1;
static int hf_feature_osd_packed_recovery  = -1;
static int hf_feature_osd_cachepool        = -1;
static int hf_feature_crush_v2             = -1;
static int hf_feature_export_peer          = -1;
static int hf_feature_osd_erasure_codes    = -1;
static int hf_feature_osd_tmap2omap        = -1;
static int hf_feature_osdmap_enc           = -1;
static int hf_feature_mds_inline_data      = -1;
static int hf_feature_crush_tunables3      = -1;
static int hf_feature_osd_primary_affinity = -1;
static int hf_feature_msgr_keepalive2      = -1;
static int hf_feature_reserved             = -1;
static int hf_connect_host_type            = -1;
static int hf_connect_seq_global           = -1;
static int hf_connect_seq                  = -1;
static int hf_connect_proto_ver            = -1;
static int hf_connect_auth_proto           = -1;
static int hf_connect_auth_len             = -1;
static int hf_flags                        = -1;
static int hf_flag_lossy                   = -1;
static int hf_connect                      = -1;
static int hf_connect_reply                = -1;
static int hf_tag                          = -1;
static int hf_ack                          = -1;
static int hf_head                         = -1;
static int hf_head_seq                     = -1;
static int hf_head_tid                     = -1;
static int hf_head_type                    = -1;
static int hf_head_priority                = -1;
static int hf_head_version                 = -1;
static int hf_head_front_len               = -1;
static int hf_head_middle_len              = -1;
static int hf_head_data_len                = -1;
static int hf_head_data_off                = -1;
static int hf_head_compat_version          = -1;
static int hf_head_reserved                = -1;
static int hf_head_crc                     = -1;
static int hf_foot                         = -1;
static int hf_foot_front_crc               = -1;
static int hf_foot_middle_crc              = -1;
static int hf_foot_data_crc                = -1;
static int hf_foot_signature               = -1;
static int hf_msg_front                    = -1;
static int hf_msg_middle                   = -1;
static int hf_msg_data                     = -1;
static int hf_paxos                        = -1;
static int hf_paxos_ver                    = -1;
static int hf_paxos_mon                    = -1;
static int hf_paxos_mon_tid                = -1;
static int hf_msg_mon_map                  = -1;
static int hf_msg_mon_map_data             = -1;
static int hf_msg_mon_map_data_len         = -1;
static int hf_msg_mon_sub                  = -1;
static int hf_msg_mon_sub_item             = -1;
static int hf_msg_mon_sub_item_len         = -1;
static int hf_msg_mon_sub_what             = -1;
static int hf_msg_mon_sub_what_len         = -1;
static int hf_msg_mon_sub_start            = -1;
static int hf_msg_mon_sub_flags            = -1;
static int hf_msg_mon_sub_flags_onetime    = -1;
static int hf_msg_mon_sub_ack              = -1;
static int hf_msg_mon_sub_ack_interval     = -1;
static int hf_msg_mon_sub_ack_fsid         = -1;
static int hf_msg_auth                     = -1;
static int hf_msg_auth_proto               = -1;
static int hf_msg_auth_payload             = -1;
static int hf_msg_auth_payload_len         = -1;
static int hf_msg_auth_monmap_epoch        = -1;
static int hf_msg_auth_reply               = -1;
static int hf_msg_auth_reply_proto         = -1;
static int hf_msg_auth_reply_result        = -1;
static int hf_msg_auth_reply_global_id     = -1;
static int hf_msg_auth_reply_data_len      = -1;
static int hf_msg_auth_reply_data          = -1;
static int hf_msg_auth_reply_msg           = -1;
static int hf_msg_auth_reply_msg_len       = -1;
static int hf_msg_osd_map                  = -1;
static int hf_msg_osd_map_fsid             = -1;
static int hf_msg_osd_map_inc              = -1;
static int hf_msg_osd_map_inc_len          = -1;
static int hf_msg_osd_map_map              = -1;
static int hf_msg_osd_map_map_len          = -1;
static int hf_msg_osd_map_epoch            = -1;
static int hf_msg_osd_map_data             = -1;
static int hf_msg_osd_map_data_len         = -1;
static int hf_msg_osd_map_oldest           = -1;
static int hf_msg_osd_map_newest           = -1;
static int hf_msg_mon_cmd                  = -1;
static int hf_msg_mon_cmd_fsid             = -1;
static int hf_msg_mon_cmd_arg              = -1;
static int hf_msg_mon_cmd_arg_len          = -1;
static int hf_msg_mon_cmd_str              = -1;
static int hf_msg_mon_cmd_str_len          = -1;
static int hf_msg_mon_cmd_ack              = -1;
static int hf_msg_mon_cmd_ack_code         = -1;
static int hf_msg_mon_cmd_ack_res          = -1;
static int hf_msg_mon_cmd_ack_res_len      = -1;
static int hf_msg_mon_cmd_ack_arg          = -1;
static int hf_msg_mon_cmd_ack_arg_len      = -1;
static int hf_msg_mon_cmd_ack_arg_str      = -1;
static int hf_msg_mon_cmd_ack_arg_str_len  = -1;
static int hf_msg_mon_cmd_ack_data         = -1;

/* @TODO: Remove before release.  Just for copying convenience.
static int hf_msg_                         = -1;
*/

#define C_NEW_FILESCOPE(klass) ((klass*)wmem_alloc(wmem_file_scope(),   sizeof(klass)))
#define C_NEW_PKTSCOPE(klass)  ((klass*)wmem_alloc(wmem_packet_scope(), sizeof(klass)))

/* Initialize the subtree pointers */
static gint ett_ceph = -1;

static const char *C_BANNER = "ceph";
enum c_banner {
	C_BANNER_LEN_MIN = 4,
	C_BANNER_LEN_MAX = 30,
};

enum c_inet {
	C_IPv4 = 0x0002,
	C_IPv6 = 0x000A
};

static const
value_string c_inet_strings[] = {
	{ C_IPv4, "IPv4" },
	{ C_IPv6, "IPv6" },
	{ 0     ,  NULL  }
};

/***** Feature Flags *****/
/* Transmuted from ceph:/src/include/ceph_features.h */
enum c_features {
	C_FEATURE_UID                  = 1 <<  0,
	C_FEATURE_NOSRCADDR            = 1 <<  1,
	C_FEATURE_MONCLOCKCHECK        = 1 <<  2,
	C_FEATURE_FLOCK                = 1 <<  3,
	C_FEATURE_SUBSCRIBE2           = 1 <<  4,
	C_FEATURE_MONNAMES             = 1 <<  5,
	C_FEATURE_RECONNECT_SEQ        = 1 <<  6,
	C_FEATURE_DIRLAYOUTHASH        = 1 <<  7,
	C_FEATURE_OBJECTLOCATOR        = 1 <<  8,
	C_FEATURE_PGID64               = 1 <<  9,
	C_FEATURE_INCSUBOSDMAP         = 1 << 10,
	C_FEATURE_PGPOOL3              = 1 << 11,
	C_FEATURE_OSDREPLYMUX          = 1 << 12,
	C_FEATURE_OSDENC               = 1 << 13,
	C_FEATURE_OMAP                 = 1 << 14,
	C_FEATURE_MONENC               = 1 << 15,
	C_FEATURE_QUERY_T              = 1 << 16,
	C_FEATURE_INDEP_PG_MAP         = 1 << 17,
	C_FEATURE_CRUSH_TUNABLES       = 1 << 18,
	C_FEATURE_CHUNKY_SCRUB         = 1 << 19,
	C_FEATURE_MON_NULLROUTE        = 1 << 20,
	C_FEATURE_MON_GV               = 1 << 21,
	C_FEATURE_BACKFILL_RESERVATION = 1 << 22,
	C_FEATURE_MSG_AUTH             = 1 << 23,
	C_FEATURE_RECOVERY_RESERVATION = 1 << 24,
	C_FEATURE_CRUSH_TUNABLES2      = 1 << 25,
	C_FEATURE_CREATEPOOLID         = 1 << 26,
	C_FEATURE_REPLY_CREATE_INODE   = 1 << 27,
	C_FEATURE_OSD_HBMSGS           = 1 << 28,
	C_FEATURE_MDSENC               = 1 << 29,
	C_FEATURE_OSDHASHPSPOOL        = 1 << 30,
	C_FEATURE_MON_SINGLE_PAXOS     = 1 << 31,
	C_FEATURE_OSD_SNAPMAPPER       = 1 <<  0,
	C_FEATURE_MON_SCRUB            = 1 <<  1,
	C_FEATURE_OSD_PACKED_RECOVERY  = 1 <<  2,
	C_FEATURE_OSD_CACHEPOOL        = 1 <<  3,
	C_FEATURE_CRUSH_V2             = 1 <<  4,
	C_FEATURE_EXPORT_PEER          = 1 <<  5,
	C_FEATURE_OSD_ERASURE_CODES    = 1 <<  6,
	C_FEATURE_OSD_TMAP2OMAP        = 1 <<  6,
	C_FEATURE_OSDMAP_ENC           = 1 <<  7,
	C_FEATURE_MDS_INLINE_DATA      = 1 <<  8,
	C_FEATURE_CRUSH_TUNABLES3      = 1 <<  9,
	C_FEATURE_OSD_PRIMARY_AFFINITY = 1 <<  9,
	C_FEATURE_MSGR_KEEPALIVE2      = 1 << 10,
	C_FEATURE_RESERVED             = 1 << 31
};

/***** Connect Message Flags *****/
enum c_flags {
	C_FLAG_LOSSY = 1 << 0,
};

/***** Message Tags *****/
enum c_tag {
	C_TAG_READY          = 0x01, /* server->client: ready for messages */
	C_TAG_RESETSESSION   = 0x02, /* server->client: reset, try again */
	C_TAG_WAIT           = 0x03, /* server->client: wait for racing incoming connection */
	C_TAG_RETRY_SESSION  = 0x04, /* server->client + cseq: try again with higher cseq */
	C_TAG_RETRY_GLOBAL   = 0x05, /* server->client + gseq: try again with higher gseq */
	C_TAG_CLOSE          = 0x06, /* closing pipe */
	C_TAG_MSG            = 0x07, /* message */
	C_TAG_ACK            = 0x08, /* message ack */
	C_TAG_KEEPALIVE      = 0x09, /* just a keepalive byte! */
	C_TAG_BADPROTOVER    = 0x0A, /* bad protocol version */
	C_TAG_BADAUTHORIZER  = 0x0B, /* bad authorizer */
	C_TAG_FEATURES       = 0x0C, /* insufficient features */
	C_TAG_SEQ            = 0x0D, /* 64-bit int follows with seen seq number */
	C_TAG_KEEPALIVE2     = 0x0E,
	C_TAG_KEEPALIVE2_ACK = 0x0F  /* keepalive reply */
};

static const
value_string c_tag_strings[] = {
	{C_TAG_READY,          "Ready for messages"                       },
	{C_TAG_RESETSESSION,   "Reset, try again"                         },
	{C_TAG_WAIT,           "Wait for racing incoming connection"      },
	{C_TAG_RETRY_SESSION,  "Try again with higher connection sequence"},
	{C_TAG_RETRY_GLOBAL,   "Try again with higher global sequence."   },
	{C_TAG_CLOSE,          "Close"                                    },
	{C_TAG_MSG,            "Message"                                  },
	{C_TAG_ACK,            "Message acknowledgment"                   },
	{C_TAG_KEEPALIVE,      "Keepalive"                                },
	{C_TAG_BADPROTOVER,    "Bad protocol version"                     },
	{C_TAG_BADAUTHORIZER,  "Bad authorizer"                           },
	{C_TAG_FEATURES,       "Insufficient features"                    },
	{C_TAG_SEQ,            "Sequence number"                          },
	{C_TAG_KEEPALIVE2,     "Keepalive"                                },
	{C_TAG_KEEPALIVE2_ACK, "keepalive reply"                          },
	{0,                    NULL                                       },
};
static const
value_string_ext c_tag_strings_ext = VALUE_STRING_EXT_INIT(c_tag_strings);

/* Extracted from the Ceph tree.
 * 
 * These are MSG_* constants for server <-> server (internal) messages. and
 * CEPH_MSG_* for client <-> server messages.  There is no functional
 * difference, just a naming convention.
 */
enum c_msg_type {
	C_CEPH_MSG_SHUTDOWN               = 0x0001,
	C_CEPH_MSG_PING                   = 0x0002,
	C_CEPH_MSG_MON_MAP                = 0x0004,
	C_CEPH_MSG_MON_GET_MAP            = 0x0005,
	C_CEPH_MSG_STATFS                 = 0x000D,
	C_CEPH_MSG_STATFS_REPLY           = 0x000E,
	C_CEPH_MSG_MON_SUBSCRIBE          = 0x000F,
	C_CEPH_MSG_MON_SUBSCRIBE_ACK      = 0x0010,
	C_CEPH_MSG_AUTH                   = 0x0011,
	C_CEPH_MSG_AUTH_REPLY             = 0x0012,
	C_CEPH_MSG_MON_GET_VERSION        = 0x0013,
	C_CEPH_MSG_MON_GET_VERSION_REPLY  = 0x0014,
	C_CEPH_MSG_MDS_MAP                = 0x0015,
	C_CEPH_MSG_CLIENT_SESSION         = 0x0016,
	C_CEPH_MSG_CLIENT_RECONNECT       = 0x0017,
	C_CEPH_MSG_CLIENT_REQUEST         = 0x0018,
	C_CEPH_MSG_CLIENT_REQUEST_FORWARD = 0x0019,
	C_CEPH_MSG_CLIENT_REPLY           = 0x001A,
	C_MSG_PAXOS                       = 0x0028,
	C_CEPH_MSG_OSD_MAP                = 0x0029,
	C_CEPH_MSG_OSD_OP                 = 0x002A,
	C_CEPH_MSG_OSD_OPREPLY            = 0x002B,
	C_CEPH_MSG_WATCH_NOTIFY           = 0x002C,
	C_MSG_FORWARD                     = 0x002E,
	C_MSG_ROUTE                       = 0x002F,
	C_CEPH_MSG_POOLOP_REPLY           = 0x0030,
	C_MSG_POOLOPREPLY                 = 0x0030,
	C_CEPH_MSG_POOLOP                 = 0x0031,
	C_MSG_POOLOP                      = 0x0031,
	C_MSG_MON_COMMAND                 = 0x0032,
	C_MSG_MON_COMMAND_ACK             = 0x0033,
	C_MSG_LOG                         = 0x0034,
	C_MSG_LOGACK                      = 0x0035,
	C_MSG_MON_OBSERVE                 = 0x0036,
	C_MSG_MON_OBSERVE_NOTIFY          = 0x0037,
	C_MSG_CLASS                       = 0x0038,
	C_MSG_CLASS_ACK                   = 0x0039,
	C_MSG_GETPOOLSTATS                = 0x003A,
	C_MSG_GETPOOLSTATSREPLY           = 0x003B,
	C_MSG_MON_GLOBAL_ID               = 0x003C,
	C_CEPH_MSG_PRIO_LOW               = 0x0040,
	C_MSG_MON_SCRUB                   = 0x0040,
	C_MSG_MON_ELECTION                = 0x0041,
	C_MSG_MON_PAXOS                   = 0x0042,
	C_MSG_MON_PROBE                   = 0x0043,
	C_MSG_MON_JOIN                    = 0x0044,
	C_MSG_MON_SYNC                    = 0x0045,
	C_MSG_OSD_PING                    = 0x0046,
	C_MSG_OSD_BOOT                    = 0x0047,
	C_MSG_OSD_FAILURE                 = 0x0048,
	C_MSG_OSD_ALIVE                   = 0x0049,
	C_MSG_OSD_MARK_ME_DOWN            = 0x004A,
	C_MSG_OSD_SUBOP                   = 0x004C,
	C_MSG_OSD_SUBOPREPLY              = 0x004D,
	C_MSG_OSD_PGTEMP                  = 0x004E,
	C_MSG_OSD_PG_NOTIFY               = 0x0050,
	C_MSG_OSD_PG_QUERY                = 0x0051,
	C_MSG_OSD_PG_SUMMARY              = 0x0052,
	C_MSG_OSD_PG_LOG                  = 0x0053,
	C_MSG_OSD_PG_REMOVE               = 0x0054,
	C_MSG_OSD_PG_INFO                 = 0x0055,
	C_MSG_OSD_PG_TRIM                 = 0x0056,
	C_MSG_PGSTATS                     = 0x0057,
	C_MSG_PGSTATSACK                  = 0x0058,
	C_MSG_OSD_PG_CREATE               = 0x0059,
	C_MSG_REMOVE_SNAPS                = 0x005A,
	C_MSG_OSD_SCRUB                   = 0x005B,
	C_MSG_OSD_PG_MISSING              = 0x005C,
	C_MSG_OSD_REP_SCRUB               = 0x005D,
	C_MSG_OSD_PG_SCAN                 = 0x005E,
	C_MSG_OSD_PG_BACKFILL             = 0x005F,
	C_MSG_COMMAND                     = 0x0061,
	C_MSG_COMMAND_REPLY               = 0x0062,
	C_MSG_OSD_BACKFILL_RESERVE        = 0x0063,
	C_MSG_MDS_BEACON                  = 0x0064,
	C_MSG_MDS_SLAVE_REQUEST           = 0x0065,
	C_MSG_MDS_TABLE_REQUEST           = 0x0066,
	C_MSG_OSD_PG_PUSH                 = 0x0069,
	C_MSG_OSD_PG_PULL                 = 0x006A,
	C_MSG_OSD_PG_PUSH_REPLY           = 0x006B,
	C_MSG_OSD_EC_WRITE                = 0x006C,
	C_MSG_OSD_EC_WRITE_REPLY          = 0x006D,
	C_MSG_OSD_EC_READ                 = 0x006E,
	C_MSG_OSD_EC_READ_REPLY           = 0x006F,
	C_CEPH_MSG_PRIO_DEFAULT           = 0x007F,
	C_MSG_OSD_RECOVERY_RESERVE        = 0x0096,
	C_CEPH_MSG_PRIO_HIGH              = 0x00C4,
	C_CEPH_MSG_PRIO_HIGHEST           = 0x00FF,
	C_MSG_MDS_RESOLVE                 = 0x0200,
	C_MSG_MDS_RESOLVEACK              = 0x0201,
	C_MSG_MDS_CACHEREJOIN             = 0x0202,
	C_MSG_MDS_DISCOVER                = 0x0203,
	C_MSG_MDS_DISCOVERREPLY           = 0x0204,
	C_MSG_MDS_INODEUPDATE             = 0x0205,
	C_MSG_MDS_DIRUPDATE               = 0x0206,
	C_MSG_MDS_CACHEEXPIRE             = 0x0207,
	C_MSG_MDS_DENTRYUNLINK            = 0x0208,
	C_MSG_MDS_FRAGMENTNOTIFY          = 0x0209,
	C_MSG_MDS_OFFLOAD_TARGETS         = 0x020A,
	C_MSG_MDS_DENTRYLINK              = 0x020C,
	C_MSG_MDS_FINDINO                 = 0x020D,
	C_MSG_MDS_FINDINOREPLY            = 0x020E,
	C_MSG_MDS_OPENINO                 = 0x020F,
	C_MSG_MDS_OPENINOREPLY            = 0x0210,
	C_MSG_MDS_LOCK                    = 0x0300,
	C_MSG_MDS_INODEFILECAPS           = 0x0301,
	C_CEPH_MSG_CLIENT_CAPS            = 0x0310,
	C_CEPH_MSG_CLIENT_LEASE           = 0x0311,
	C_CEPH_MSG_CLIENT_SNAP            = 0x0312,
	C_CEPH_MSG_CLIENT_CAPRELEASE      = 0x0313,
	C_MSG_MDS_EXPORTDIRDISCOVER       = 0x0449,
	C_MSG_MDS_EXPORTDIRDISCOVERACK    = 0x0450,
	C_MSG_MDS_EXPORTDIRCANCEL         = 0x0451,
	C_MSG_MDS_EXPORTDIRPREP           = 0x0452,
	C_MSG_MDS_EXPORTDIRPREPACK        = 0x0453,
	C_MSG_MDS_EXPORTDIRWARNING        = 0x0454,
	C_MSG_MDS_EXPORTDIRWARNINGACK     = 0x0455,
	C_MSG_MDS_EXPORTDIR               = 0x0456,
	C_MSG_MDS_EXPORTDIRACK            = 0x0457,
	C_MSG_MDS_EXPORTDIRNOTIFY         = 0x0458,
	C_MSG_MDS_EXPORTDIRNOTIFYACK      = 0x0459,
	C_MSG_MDS_EXPORTDIRFINISH         = 0x0460,
	C_MSG_MDS_EXPORTCAPS              = 0x0470,
	C_MSG_MDS_EXPORTCAPSACK           = 0x0471,
	C_MSG_MDS_HEARTBEAT               = 0x0500,
	C_MSG_TIMECHECK                   = 0x0600,
	C_MSG_MON_HEALTH                  = 0x0601,
};

static const
value_string c_msg_type_strings[] = {
	{C_CEPH_MSG_SHUTDOWN,               "CEPH_MSG_SHUTDOWN"               },
	{C_CEPH_MSG_PING,                   "CEPH_MSG_PING"                   },
	{C_CEPH_MSG_MON_MAP,                "CEPH_MSG_MON_MAP"                },
	{C_CEPH_MSG_MON_GET_MAP,            "CEPH_MSG_MON_GET_MAP"            },
	{C_CEPH_MSG_STATFS,                 "CEPH_MSG_STATFS"                 },
	{C_CEPH_MSG_STATFS_REPLY,           "CEPH_MSG_STATFS_REPLY"           },
	{C_CEPH_MSG_MON_SUBSCRIBE,          "CEPH_MSG_MON_SUBSCRIBE"          },
	{C_CEPH_MSG_MON_SUBSCRIBE_ACK,      "CEPH_MSG_MON_SUBSCRIBE_ACK"      },
	{C_CEPH_MSG_AUTH,                   "CEPH_MSG_AUTH"                   },
	{C_CEPH_MSG_AUTH_REPLY,             "CEPH_MSG_AUTH_REPLY"             },
	{C_CEPH_MSG_MON_GET_VERSION,        "CEPH_MSG_MON_GET_VERSION"        },
	{C_CEPH_MSG_MON_GET_VERSION_REPLY,  "CEPH_MSG_MON_GET_VERSION_REPLY"  },
	{C_CEPH_MSG_MDS_MAP,                "CEPH_MSG_MDS_MAP"                },
	{C_CEPH_MSG_CLIENT_SESSION,         "CEPH_MSG_CLIENT_SESSION"         },
	{C_CEPH_MSG_CLIENT_RECONNECT,       "CEPH_MSG_CLIENT_RECONNECT"       },
	{C_CEPH_MSG_CLIENT_REQUEST,         "CEPH_MSG_CLIENT_REQUEST"         },
	{C_CEPH_MSG_CLIENT_REQUEST_FORWARD, "CEPH_MSG_CLIENT_REQUEST_FORWARD" },
	{C_CEPH_MSG_CLIENT_REPLY,           "CEPH_MSG_CLIENT_REPLY"           },
	{C_MSG_PAXOS,                       "MSG_PAXOS"                       },
	{C_CEPH_MSG_OSD_MAP,                "CEPH_MSG_OSD_MAP"                },
	{C_CEPH_MSG_OSD_OP,                 "CEPH_MSG_OSD_OP"                 },
	{C_CEPH_MSG_OSD_OPREPLY,            "CEPH_MSG_OSD_OPREPLY"            },
	{C_CEPH_MSG_WATCH_NOTIFY,           "CEPH_MSG_WATCH_NOTIFY"           },
	{C_MSG_FORWARD,                     "MSG_FORWARD"                     },
	{C_MSG_ROUTE,                       "MSG_ROUTE"                       },
	{C_CEPH_MSG_POOLOP_REPLY,           "CEPH_MSG_POOLOP_REPLY"           },
	{C_MSG_POOLOPREPLY,                 "MSG_POOLOPREPLY"                 },
	{C_CEPH_MSG_POOLOP,                 "CEPH_MSG_POOLOP"                 },
	{C_MSG_POOLOP,                      "MSG_POOLOP"                      },
	{C_MSG_MON_COMMAND,                 "MSG_MON_COMMAND"                 },
	{C_MSG_MON_COMMAND_ACK,             "MSG_MON_COMMAND_ACK"             },
	{C_MSG_LOG,                         "MSG_LOG"                         },
	{C_MSG_LOGACK,                      "MSG_LOGACK"                      },
	{C_MSG_MON_OBSERVE,                 "MSG_MON_OBSERVE"                 },
	{C_MSG_MON_OBSERVE_NOTIFY,          "MSG_MON_OBSERVE_NOTIFY"          },
	{C_MSG_CLASS,                       "MSG_CLASS"                       },
	{C_MSG_CLASS_ACK,                   "MSG_CLASS_ACK"                   },
	{C_MSG_GETPOOLSTATS,                "MSG_GETPOOLSTATS"                },
	{C_MSG_GETPOOLSTATSREPLY,           "MSG_GETPOOLSTATSREPLY"           },
	{C_MSG_MON_GLOBAL_ID,               "MSG_MON_GLOBAL_ID"               },
	{C_CEPH_MSG_PRIO_LOW,               "CEPH_MSG_PRIO_LOW"               },
	{C_MSG_MON_SCRUB,                   "MSG_MON_SCRUB"                   },
	{C_MSG_MON_ELECTION,                "MSG_MON_ELECTION"                },
	{C_MSG_MON_PAXOS,                   "MSG_MON_PAXOS"                   },
	{C_MSG_MON_PROBE,                   "MSG_MON_PROBE"                   },
	{C_MSG_MON_JOIN,                    "MSG_MON_JOIN"                    },
	{C_MSG_MON_SYNC,                    "MSG_MON_SYNC"                    },
	{C_MSG_OSD_PING,                    "MSG_OSD_PING"                    },
	{C_MSG_OSD_BOOT,                    "MSG_OSD_BOOT"                    },
	{C_MSG_OSD_FAILURE,                 "MSG_OSD_FAILURE"                 },
	{C_MSG_OSD_ALIVE,                   "MSG_OSD_ALIVE"                   },
	{C_MSG_OSD_MARK_ME_DOWN,            "MSG_OSD_MARK_ME_DOWN"            },
	{C_MSG_OSD_SUBOP,                   "MSG_OSD_SUBOP"                   },
	{C_MSG_OSD_SUBOPREPLY,              "MSG_OSD_SUBOPREPLY"              },
	{C_MSG_OSD_PGTEMP,                  "MSG_OSD_PGTEMP"                  },
	{C_MSG_OSD_PG_NOTIFY,               "MSG_OSD_PG_NOTIFY"               },
	{C_MSG_OSD_PG_QUERY,                "MSG_OSD_PG_QUERY"                },
	{C_MSG_OSD_PG_SUMMARY,              "MSG_OSD_PG_SUMMARY"              },
	{C_MSG_OSD_PG_LOG,                  "MSG_OSD_PG_LOG"                  },
	{C_MSG_OSD_PG_REMOVE,               "MSG_OSD_PG_REMOVE"               },
	{C_MSG_OSD_PG_INFO,                 "MSG_OSD_PG_INFO"                 },
	{C_MSG_OSD_PG_TRIM,                 "MSG_OSD_PG_TRIM"                 },
	{C_MSG_PGSTATS,                     "MSG_PGSTATS"                     },
	{C_MSG_PGSTATSACK,                  "MSG_PGSTATSACK"                  },
	{C_MSG_OSD_PG_CREATE,               "MSG_OSD_PG_CREATE"               },
	{C_MSG_REMOVE_SNAPS,                "MSG_REMOVE_SNAPS"                },
	{C_MSG_OSD_SCRUB,                   "MSG_OSD_SCRUB"                   },
	{C_MSG_OSD_PG_MISSING,              "MSG_OSD_PG_MISSING"              },
	{C_MSG_OSD_REP_SCRUB,               "MSG_OSD_REP_SCRUB"               },
	{C_MSG_OSD_PG_SCAN,                 "MSG_OSD_PG_SCAN"                 },
	{C_MSG_OSD_PG_BACKFILL,             "MSG_OSD_PG_BACKFILL"             },
	{C_MSG_COMMAND,                     "MSG_COMMAND"                     },
	{C_MSG_COMMAND_REPLY,               "MSG_COMMAND_REPLY"               },
	{C_MSG_OSD_BACKFILL_RESERVE,        "MSG_OSD_BACKFILL_RESERVE"        },
	{C_MSG_MDS_BEACON,                  "MSG_MDS_BEACON"                  },
	{C_MSG_MDS_SLAVE_REQUEST,           "MSG_MDS_SLAVE_REQUEST"           },
	{C_MSG_MDS_TABLE_REQUEST,           "MSG_MDS_TABLE_REQUEST"           },
	{C_MSG_OSD_PG_PUSH,                 "MSG_OSD_PG_PUSH"                 },
	{C_MSG_OSD_PG_PULL,                 "MSG_OSD_PG_PULL"                 },
	{C_MSG_OSD_PG_PUSH_REPLY,           "MSG_OSD_PG_PUSH_REPLY"           },
	{C_MSG_OSD_EC_WRITE,                "MSG_OSD_EC_WRITE"                },
	{C_MSG_OSD_EC_WRITE_REPLY,          "MSG_OSD_EC_WRITE_REPLY"          },
	{C_MSG_OSD_EC_READ,                 "MSG_OSD_EC_READ"                 },
	{C_MSG_OSD_EC_READ_REPLY,           "MSG_OSD_EC_READ_REPLY"           },
	{C_CEPH_MSG_PRIO_DEFAULT,           "CEPH_MSG_PRIO_DEFAULT"           },
	{C_MSG_OSD_RECOVERY_RESERVE,        "MSG_OSD_RECOVERY_RESERVE"        },
	{C_CEPH_MSG_PRIO_HIGH,              "CEPH_MSG_PRIO_HIGH"              },
	{C_CEPH_MSG_PRIO_HIGHEST,           "CEPH_MSG_PRIO_HIGHEST"           },
	{C_MSG_MDS_RESOLVE,                 "MSG_MDS_RESOLVE"                 },
	{C_MSG_MDS_RESOLVEACK,              "MSG_MDS_RESOLVEACK"              },
	{C_MSG_MDS_CACHEREJOIN,             "MSG_MDS_CACHEREJOIN"             },
	{C_MSG_MDS_DISCOVER,                "MSG_MDS_DISCOVER"                },
	{C_MSG_MDS_DISCOVERREPLY,           "MSG_MDS_DISCOVERREPLY"           },
	{C_MSG_MDS_INODEUPDATE,             "MSG_MDS_INODEUPDATE"             },
	{C_MSG_MDS_DIRUPDATE,               "MSG_MDS_DIRUPDATE"               },
	{C_MSG_MDS_CACHEEXPIRE,             "MSG_MDS_CACHEEXPIRE"             },
	{C_MSG_MDS_DENTRYUNLINK,            "MSG_MDS_DENTRYUNLINK"            },
	{C_MSG_MDS_FRAGMENTNOTIFY,          "MSG_MDS_FRAGMENTNOTIFY"          },
	{C_MSG_MDS_OFFLOAD_TARGETS,         "MSG_MDS_OFFLOAD_TARGETS"         },
	{C_MSG_MDS_DENTRYLINK,              "MSG_MDS_DENTRYLINK"              },
	{C_MSG_MDS_FINDINO,                 "MSG_MDS_FINDINO"                 },
	{C_MSG_MDS_FINDINOREPLY,            "MSG_MDS_FINDINOREPLY"            },
	{C_MSG_MDS_OPENINO,                 "MSG_MDS_OPENINO"                 },
	{C_MSG_MDS_OPENINOREPLY,            "MSG_MDS_OPENINOREPLY"            },
	{C_MSG_MDS_LOCK,                    "MSG_MDS_LOCK"                    },
	{C_MSG_MDS_INODEFILECAPS,           "MSG_MDS_INODEFILECAPS"           },
	{C_CEPH_MSG_CLIENT_CAPS,            "CEPH_MSG_CLIENT_CAPS"            },
	{C_CEPH_MSG_CLIENT_LEASE,           "CEPH_MSG_CLIENT_LEASE"           },
	{C_CEPH_MSG_CLIENT_SNAP,            "CEPH_MSG_CLIENT_SNAP"            },
	{C_CEPH_MSG_CLIENT_CAPRELEASE,      "CEPH_MSG_CLIENT_CAPRELEASE"      },
	{C_MSG_MDS_EXPORTDIRDISCOVER,       "MSG_MDS_EXPORTDIRDISCOVER"       },
	{C_MSG_MDS_EXPORTDIRDISCOVERACK,    "MSG_MDS_EXPORTDIRDISCOVERACK"    },
	{C_MSG_MDS_EXPORTDIRCANCEL,         "MSG_MDS_EXPORTDIRCANCEL"         },
	{C_MSG_MDS_EXPORTDIRPREP,           "MSG_MDS_EXPORTDIRPREP"           },
	{C_MSG_MDS_EXPORTDIRPREPACK,        "MSG_MDS_EXPORTDIRPREPACK"        },
	{C_MSG_MDS_EXPORTDIRWARNING,        "MSG_MDS_EXPORTDIRWARNING"        },
	{C_MSG_MDS_EXPORTDIRWARNINGACK,     "MSG_MDS_EXPORTDIRWARNINGACK"     },
	{C_MSG_MDS_EXPORTDIR,               "MSG_MDS_EXPORTDIR"               },
	{C_MSG_MDS_EXPORTDIRACK,            "MSG_MDS_EXPORTDIRACK"            },
	{C_MSG_MDS_EXPORTDIRNOTIFY,         "MSG_MDS_EXPORTDIRNOTIFY"         },
	{C_MSG_MDS_EXPORTDIRNOTIFYACK,      "MSG_MDS_EXPORTDIRNOTIFYACK"      },
	{C_MSG_MDS_EXPORTDIRFINISH,         "MSG_MDS_EXPORTDIRFINISH"         },
	{C_MSG_MDS_EXPORTCAPS,              "MSG_MDS_EXPORTCAPS"              },
	{C_MSG_MDS_EXPORTCAPSACK,           "MSG_MDS_EXPORTCAPSACK"           },
	{C_MSG_MDS_HEARTBEAT,               "MSG_MDS_HEARTBEAT"               },
	{C_MSG_TIMECHECK,                   "MSG_TIMECHECK"                   },
	{C_MSG_MON_HEALTH,                  "MSG_MON_HEALTH"                  },
	{0,                                 NULL                              }
};
static const
value_string_ext c_msg_type_strings_ext = VALUE_STRING_EXT_INIT(c_msg_type_strings);

typedef enum _c_node_type {
	C_NODE_TYPE_UNKNOWN = 0x00,
	C_NODE_TYPE_MON     = 0x01,
	C_NODE_TYPE_MDS     = 0x02,
	C_NODE_TYPE_OSD     = 0x04,
	C_NODE_TYPE_CLIENT  = 0x08,
	C_NODE_TYPE_AUTH    = 0x20
} c_node_type;

static const
value_string c_node_type_strings[] = {
	{C_NODE_TYPE_UNKNOWN, "Unknown"              },
	{C_NODE_TYPE_MON,     "Monitor"              },
	{C_NODE_TYPE_MDS,     "Meta Data Server"     },
	{C_NODE_TYPE_OSD,     "Object Storage Daemon"},
	{C_NODE_TYPE_CLIENT,  "Client"               },
	{C_NODE_TYPE_AUTH,    "Authentication Server"},
	{0,                   NULL                   }
};
static const
value_string c_node_type_abbr_strings[] = {
	{C_NODE_TYPE_UNKNOWN, "unknown"},
	{C_NODE_TYPE_MON,     "mon"    },
	{C_NODE_TYPE_MDS,     "mds"    },
	{C_NODE_TYPE_OSD,     "osd"    },
	{C_NODE_TYPE_CLIENT,  "client" },
	{C_NODE_TYPE_AUTH,    "auth"   },
	{0,                   NULL     }
};

enum c_mon_sub_flags {
	C_MON_SUB_FLAG_ONETIME = 0x01
};

typedef enum _c_state {
	C_STATE_NEW,
	C_STATE_OPEN
} c_state;

typedef struct _c_node {
	c_node_type type;
	address addr;
	guint16 port;
	c_state state;
} c_node;

static
void c_node_init(c_node *n)
{
	n->type = C_NODE_TYPE_UNKNOWN;
	/* @HELP: n->addr is there a sane way to initialize this? */
	n->port = 0xFFFF;
	n->state = C_STATE_NEW;
}

static
c_node *c_node_copy(c_node *src, c_node *dst)
{
	dst->type = src->type;
	copy_address(&dst->addr, &src->addr);
	dst->port = src->port;
	dst->state = src->state;
	
	return dst;
}

typedef struct _c_conv_data {
	c_node client; /* The node that initiated this connection. */
	c_node server; /* The other node. */
} c_conv_data;

static
void c_conv_data_init(c_conv_data *d)
{
	c_node_init(&d->client);
	c_node_init(&d->server);
}

static
c_conv_data *c_conv_data_copy(c_conv_data *src, c_conv_data *dst)
{
	c_node_copy(&src->client, &dst->client);
	c_node_copy(&src->server, &dst->server);
	
	return dst;
}

static
c_conv_data *c_conv_data_clone(c_conv_data *d)
{
	return c_conv_data_copy(d, C_NEW_FILESCOPE(c_conv_data));
}

static
c_conv_data* c_conv_data_new(void)
{
	c_conv_data *r;
	r = C_NEW_FILESCOPE(c_conv_data);
	c_conv_data_init(r);
	return r;
}

typedef struct _c_header {
	guint64 seq;
	guint64 tid;
	guint16 type;
	guint8  priority;
	guint16 ver;
} c_header;

static
void c_header_init(c_header *h)
{
	h->seq      = 0;
	h->tid      = 0;
	h->type     = 0;
	h->priority = 0;
	h->ver      = 0;
}

typedef struct _c_pkt_data {
	conversation_t *conv; /* The wireshark conversation. */
	c_conv_data *convd;   /* The Ceph conversation data. */
	c_node *src;          /* The node in convd that sent this message. */
	c_node *dst;          /* The node in convd that is receiving this message. */
	
	proto_item  *item_root; /* The root proto_item for the message. */
	packet_info *pinfo;
	
	c_header header;      /* The MSG header. */
} c_pkt_data;

/** Initialize the packet data.
 * 
 * The packet data structure holds all of the Ceph-specific data that is needed
 * to dissect the protocol.  This function initializes the structure.
 * 
 * This function grabs the appropriate data either from previous packets in the
 * dissection, or creating a new data for new conversations.
 * 
 * Lastly this function saves the state before every packet so that if we are
 * asked to dissect the same packet again the same state will be used as when
 * it was dissected initially.
 */
static void
c_pkt_data_init(c_pkt_data *d, packet_info *pinfo, guint offset)
{
	/* Get conversation to store/retrieve connection data. */
	d->conv = find_or_create_conversation(pinfo);
	g_assert(d->conv);
	
	if (pinfo->fd->flags.visited)
	{
		/* Retrieve the saved state. */
		d->convd = (c_conv_data*)p_get_proto_data(wmem_file_scope(), pinfo, proto_ceph, offset);
		/* Make a copy and use that so we don't mess up the original. */
		d->convd = c_conv_data_copy(d->convd, C_NEW_PKTSCOPE(c_conv_data));
	}
	else
	{
		/*
			If there is no saved state get the state from dissecting the
			last packet.
		*/
		d->convd = (c_conv_data*)conversation_get_proto_data(d->conv, proto_ceph);
	}
	
	if (!d->convd) /* New conversation. */
	{
		d->convd = c_conv_data_new();
		
		/* Note: Server sends banner first. */
		
		copy_address(&d->convd->server.addr, &pinfo->src);
		d->convd->server.port = pinfo->srcport;
		copy_address(&d->convd->client.addr, &pinfo->dst);
		d->convd->client.port = pinfo->destport;
		conversation_add_proto_data(d->conv, proto_ceph, d->convd);
	}
	g_assert(d->convd);
	
	if (!pinfo->fd->flags.visited)
	{
		/*
			Save a copy of the state for next time we dissect this packet.
		*/
		p_add_proto_data(wmem_file_scope(), pinfo, proto_ceph, offset,
		                                    c_conv_data_clone(d->convd));
	}
	
	/*** Set up src and dst pointers correctly. ***/
	if (ADDRESSES_EQUAL(&d->convd->client.addr, &pinfo->src) &&
	    d->convd->client.port == pinfo->srcport)
	{
		d->src = &d->convd->client;
		d->dst = &d->convd->server;
	}
	else
	{
		d->src = &d->convd->server;
		d->dst = &d->convd->client;
	}
	g_assert(d->src);
	g_assert(d->dst);
	
	c_header_init(&d->header);
	d->item_root = NULL;
	d->pinfo    = pinfo;
}

/** Check if packet is from the client.
 * 
 * Returns true iff the packet is from the client.
 */
static
gboolean c_from_client(c_pkt_data *d)
{
	return d->src == &d->convd->client;
}

/** Check if packet is from the server.
 * 
 * See c_from_client()
 */
static
gboolean c_from_server(c_pkt_data *d)
{
	return d->src == &d->convd->server;
}

static
void c_set_type(c_pkt_data *data, const char *type)
{
	col_set_str(data->pinfo->cinfo, COL_INFO, type);
	proto_item_append_text(data->item_root, " %s", type);
}

/***** Protocol Dissector *****/

enum c_ressembly {
	C_NEEDMORE = 0
};

/*** Data Structure Dissectors ***/

enum c_size_sockaddr {
	C_SIZE_SOCKADDR_STORAGE = 128
};

typedef struct _c_sockaddr {
	const gchar *str;
	const gchar *addr_str;
	
	guint16 af;
	guint16 port;
} c_sockaddr;

static
guint c_dissect_sockaddr(proto_tree *root, c_sockaddr *sdata,
                         tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	c_sockaddr d;
	
	/*
	struct sockaddr_storage {
		guint16 family;
		guint8  pad[???]; // Implementation defined.
	};
	struct sockaddr_in {
		guint16 family;
		guint16 port;
		guint32 addr;
		guint8  pad[8];
	};
	struct sockaddr_in6 {
		guint16 family;
		guint16 port;
		guint32 flow;
		guint8  addr[16];
		guint32 scope;
	};
	*/
	
	ti = proto_tree_add_item(root, hf_sockaddr,
	                         tvb, off, C_SIZE_SOCKADDR_STORAGE, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_sockaddr);
	
	d.af = tvb_get_ntohs(tvb, off);
	
	proto_tree_add_item(tree, hf_inet_family, tvb, off, 2, ENC_BIG_ENDIAN);
	
	switch (d.af) {
	case C_IPv4:
		d.port     = tvb_get_ntohs(tvb, off+2);
		d.addr_str = tvb_ip_to_str(tvb, off+4);
		
		proto_tree_add_item(tree, hf_port, tvb, off+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_addr_ipv4, tvb, off+4, 4, ENC_BIG_ENDIAN);
		break;
	case C_IPv6: //@UNTESTED
		d.port     = tvb_get_ntohs (tvb, off+2);
		d.addr_str = tvb_ip6_to_str(tvb, off+8);
		
		proto_tree_add_item(tree, hf_port, tvb, off+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_addr_ipv6, tvb, off+8, 16, ENC_NA);
		break;
	default:
		d.port = 0;
		d.addr_str = "Unknown INET";
	}
	off += C_SIZE_SOCKADDR_STORAGE; // Skip over sockaddr_storage.
	
	d.str = wmem_strdup_printf(wmem_packet_scope(), "%s:%"G_GINT16_MODIFIER"u",
	                           d.addr_str,
	                           d.port);
	proto_item_append_text(ti, ": %s", d.str);
	
	if (sdata) *sdata = d;
	
	return off;
}

enum c_size_entity_addr {
	C_SIZE_ENTITY_ADDR = 4 + 4 + C_SIZE_SOCKADDR_STORAGE
};

static
guint c_dissect_entity_addr(proto_tree *root, int hf,
                            tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint32     type;
	c_sockaddr  addr;
	
	ti = proto_tree_add_item(root, hf, tvb, off, C_SIZE_ENTITY_ADDR, ENC_NA);
	tree = proto_item_add_subtree(ti, hf);
	
	type = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_node_type,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_node_nonce,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	off = c_dissect_sockaddr(tree, &addr, tvb, off, data);
	
	proto_item_append_text(ti, ", Type: %s, Address: %s",
	                       val_to_str(type, c_node_type_strings, "Uknown (0x%08x)"),
	                       addr.str);
	
	return off;
}

enum c_size_entity_name {
	C_SIZE_ENTITY_NAME = 9
};

static
guint c_dissect_entity_name(proto_tree *root,
                            tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	/* From ceph:/src/include/msgr.h
	struct ceph_entity_name {
		__u8 type;      // CEPH_ENTITY_TYPE_*
		__le64 num;
	} __attribute__ ((packed));
	*/
	
	proto_item *ti;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, hf_node_name, tvb,
	                         off, C_SIZE_ENTITY_NAME,
	                         ENC_NA);
	tree = proto_item_add_subtree(ti, hf_node_name);
	
	proto_tree_add_item(tree, hf_node_type,
	                    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;
	proto_tree_add_item(tree, hf_node_id,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	return off;
}

static
guint c_dissect_features(proto_tree *tree,
                      tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	static const int *lowword[] = {
		&hf_feature_uid,
		&hf_feature_nosrcaddr,
		&hf_feature_monclockcheck,
		&hf_feature_flock,
		&hf_feature_subscribe2,
		&hf_feature_monnames,
		&hf_feature_reconnect_seq,
		&hf_feature_dirlayouthash,
		&hf_feature_objectlocator,
		&hf_feature_pgid64,
		&hf_feature_incsubosdmap,
		&hf_feature_pgpool3,
		&hf_feature_osdreplymux,
		&hf_feature_osdenc,
		&hf_feature_omap,
		&hf_feature_monenc,
		&hf_feature_query_t,
		&hf_feature_indep_pg_map,
		&hf_feature_crush_tunables,
		&hf_feature_chunky_scrub,
		&hf_feature_mon_nullroute,
		&hf_feature_mon_gv,
		&hf_feature_backfill_reservation,
		&hf_feature_msg_auth,
		&hf_feature_recovery_reservation,
		&hf_feature_crush_tunables2,
		&hf_feature_createpoolid,
		&hf_feature_reply_create_inode,
		&hf_feature_osd_hbmsgs,
		&hf_feature_mdsenc,
		&hf_feature_osdhashpspool,
		&hf_feature_mon_single_paxos,
		NULL
	};
	static const int *highword[] = {
		&hf_feature_osd_snapmapper,
		&hf_feature_mon_scrub,
		&hf_feature_osd_packed_recovery,
		&hf_feature_osd_cachepool,
		&hf_feature_crush_v2,
		&hf_feature_export_peer,
		&hf_feature_osd_erasure_codes,
		&hf_feature_osd_tmap2omap,
		&hf_feature_osdmap_enc,
		&hf_feature_mds_inline_data,
		&hf_feature_crush_tunables3,
		&hf_feature_osd_primary_affinity,
		&hf_feature_msgr_keepalive2,
		&hf_feature_reserved,
		NULL
	};
	
	/* Wireshark doesn't have support for 64 bit bitfields so dissect as
	   two 32 bit ones. */
	
	proto_tree_add_bitmask(tree, tvb, off, hf_features_low, hf_features_low,
	                       lowword, ENC_LITTLE_ENDIAN);
	off += 4;
	
	proto_tree_add_bitmask(tree, tvb, off, hf_features_high, hf_features_high,
	                       highword, ENC_LITTLE_ENDIAN);
	off += 4;
	
	return off;
}

static
guint c_dissect_flags(proto_tree *tree,
                      tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	static const int *flags[] = {
		&hf_flag_lossy,
		NULL
	};
	
	proto_tree_add_bitmask(tree, tvb, off, hf_flags, hf_flags,
	                       flags, ENC_LITTLE_ENDIAN);
	
	return off+1;
}

/** Dissect a length-delimited binary blob.
 */
static
guint c_dissect_blob(proto_tree *root, int hf_data, int hf_len,
                     tvbuff_t *tvb, guint off)
{
	proto_item *ti;
	proto_tree *tree;
	guint32 size;
	
	size = tvb_get_letohl(tvb, off);
	
	ti = proto_tree_add_item(root, hf_data, tvb, off+4, size, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_data);
	
	proto_tree_add_item(tree, hf_blob_size,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_blob_data,
	                    tvb, off, size, ENC_LITTLE_ENDIAN);
	off += size;
	
	return off;
}

typedef struct _c_str {
	char    *str;
	guint32  size;
} c_str;

/** Dissect a length-delimited string.
 */
static
guint c_dissect_str(proto_tree *root, int hf, c_str *out,
                     tvbuff_t *tvb, guint off)
{
	proto_item *ti;
	proto_tree *tree;
	c_str d;
	
	d.size = tvb_get_letohl(tvb, off);
	d.str  = tvb_get_string_enc(wmem_packet_scope(), tvb, off+4, d.size, ENC_ASCII);
	
	ti = proto_tree_add_string_format_value(root, hf, tvb, off, 4+d.size,
	                                        d.str,
	                                        "%s", d.str);
	tree = proto_item_add_subtree(ti, hf);
	
	proto_tree_add_item(tree, hf_string_size,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_string_data,
	                    tvb, off, d.size, ENC_LITTLE_ENDIAN);
	off += d.size;
	
	if (out) *out = d;
	
	return off;
}

enum c_size_timespec {
	C_SIZE_TIMESPEC = 4 + 4
};

static
guint c_dissect_timespec(proto_tree *root,
                         tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, hf_time, tvb,
	                         off, C_SIZE_TIMESPEC,
	                         ENC_NA);
	tree = proto_item_add_subtree(ti, hf_time);
	
	proto_tree_add_item(tree, hf_time_sec,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_time_nsec,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	return off;
}

enum c_size_paxos {
	C_SIZE_PAXOS = 18
};

static
guint c_dissect_paxos(proto_tree *root,
                      tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, hf_paxos,
	                         tvb, off, C_SIZE_PAXOS, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_paxos);
	
	proto_tree_add_item(tree, hf_paxos_ver,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_paxos_mon,
	                    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	proto_tree_add_item(tree, hf_paxos_mon_tid,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	return off;
}


/*** Message Dissectors ***/

/** Used to handle unknown messages.
 * 
 * Simply displays the front, middle and data portions as binary strings.
 */
static
guint c_dissect_msg_unknown(proto_tree *tree,
                          tvbuff_t *tvb,
                          guint front_len, guint middle_len, guint data_len,
                          c_pkt_data *data)
{
	guint off = 0;
	
	c_set_type(data, "MSG");
	proto_item_append_text(data->item_root,
	                       ", Front Len: %u, Middle Len: %u, Data Len %u",
	                       front_len, middle_len, data_len);
	
	if (front_len) {
		proto_tree_add_item(tree, hf_msg_front,
		                    tvb, off, front_len, ENC_NA);
		off += front_len;
	}
	if (middle_len) {
		proto_tree_add_item(tree, hf_msg_middle,
		                    tvb, off, middle_len, ENC_NA);
		off += middle_len;
	}
	if (data_len) {
		proto_tree_add_item(tree, hf_msg_data,
		                    tvb, off, data_len, ENC_NA);
		off += data_len;
	}
	
	return off;
}

static
guint c_dissect_msg_mon_map(proto_tree *root,
                           tvbuff_t *tvb,
                           guint front_len, guint middle_len _U_, guint data_len _U_,
                           c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	
	/* ceph:/src/messages/MMonMap.h */
	
	c_set_type(data, "Mon Map");
	
	ti = proto_tree_add_item(root, hf_msg_mon_map,
	                         tvb, 0, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_mon_map);
	
	return c_dissect_blob(tree, hf_msg_mon_map_data, hf_msg_mon_map_data_len,
	                      tvb, 0);
	
	//@TODO: Parse Mon Map.
}

static
guint c_dissect_msg_mon_sub(proto_tree *tree,
                           tvbuff_t *tvb,
                           guint front_len, guint middle_len _U_, guint data_len _U_,
                           c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *subtree;
	guint off = 0;
	guint len;
	gboolean first = 1;
	c_str str;
	
	/* ceph:/src/messages/MMonSubscribe.h */
	
	c_set_type(data, "Mon Subscribe");
	proto_item_append_text(data->item_root, ", To:");
	
	len = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_sub_item_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	while (len--)
	{
		/* From ceph:/src/include/ceph_fs.h
		struct ceph_mon_subscribe_item {
			__le64 start;
			__u8 flags;
		} __attribute__ ((packed))
		
		//@TODO: Old subscription item.
		From ceph:/src/messages/MMonSubscribe.h
		struct ceph_mon_subscribe_item_old {
			__le64 unused;
			__le64 have;
			__u8 onetime;
		} __attribute__ ((packed));
		*/
		
		ti = proto_tree_add_item(tree, hf_msg_mon_sub_item,
		                         tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, hf_msg_mon_sub_item);
		
		off = c_dissect_str(subtree, hf_msg_mon_sub_what, &str, tvb, off);
		
		proto_item_append_text(data->item_root, "%c%s",
		                       first? ' ':',',
		                       str.str);
		first = 0;
		
		proto_item_append_text(ti, ", What: %s, Starting: %"G_GUINT64_FORMAT,
		                       str.str,
		                       tvb_get_letoh64(tvb, off));
		
		proto_tree_add_item(subtree, hf_msg_mon_sub_start,
		                    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		
		/* Flags */
		ti2 = proto_tree_add_item(subtree, hf_msg_mon_sub_flags,
		                          tvb, off, 1, ENC_LITTLE_ENDIAN);
		/* Reuse subtree variable for flags. */
		subtree = proto_item_add_subtree(ti2, hf_msg_mon_sub_flags);
		proto_tree_add_item(subtree, hf_msg_mon_sub_flags_onetime,
		                    tvb, off, 1, ENC_LITTLE_ENDIAN);
		off += 1;
		
		proto_item_set_end(ti, tvb, off);
	}
	
	return off;
}

static
guint c_dissect_msg_mon_sub_ack(proto_tree *root,
                               tvbuff_t *tvb,
                               guint front_len, guint middle_len _U_, guint data_len _U_,
                               c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	
	/* ceph:/src/messages/MMonSubscribeAck.h */
	
	c_set_type(data, "Mon Subscribe Ack");
	
	ti = proto_tree_add_item(root, hf_msg_mon_sub_ack,
	                         tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_mon_sub_ack);
	
	proto_tree_add_item(tree, hf_msg_mon_sub_ack_interval,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_msg_mon_sub_ack_fsid,
	                    tvb, off, 16, ENC_LITTLE_ENDIAN);
	off += 16;
	
	return off;
}

static
guint c_dissect_msg_auth(proto_tree *root,
                        tvbuff_t *tvb,
                        guint front_len, guint middle_len _U_, guint data_len _U_,
                        c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	
	/* ceph:/src/messages/MAuth.h */
	
	c_set_type(data, "Auth");
	
	off = c_dissect_paxos(root, tvb, off, data);
	
	ti = proto_tree_add_item(root, hf_msg_auth,
	                         tvb, off, front_len-off, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_auth);
	
	proto_item_append_text(data->item_root, ", Proto: 0x%02x",
	                       tvb_get_letohl(tvb, off));
	proto_tree_add_item(tree, hf_msg_auth_proto,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	off = c_dissect_blob(tree, hf_msg_auth_payload, hf_msg_auth_payload_len,
	                     tvb, off);
	
	//@TODO: Parse auth.
	
	if (off+4 == front_len) { /* If there is an epoch. */
		proto_tree_add_item(tree, hf_msg_auth_monmap_epoch,
		                    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}
	
	return off;
}

static
guint c_dissect_msg_auth_reply(proto_tree *root,
                              tvbuff_t *tvb,
                              guint front_len, guint middle_len _U_, guint data_len _U_,
                              c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	
	/* ceph:/src/messages/MAuthReply.h */
	
	c_set_type(data, "Auth Reply");
	
	ti = proto_tree_add_item(root, hf_msg_auth_reply,
	                         tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_auth_reply);
	
	proto_item_append_text(data->item_root, ", Proto: %x",
	                       tvb_get_letohl(tvb, off));
	proto_tree_add_item(tree, hf_msg_auth_reply_proto,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_msg_auth_reply_result,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_msg_auth_reply_global_id,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	off = c_dissect_blob(tree, hf_msg_auth_reply_data, hf_msg_auth_reply_data_len,
	                     tvb, off);
	off = c_dissect_blob(tree, hf_msg_auth_reply_msg, hf_msg_auth_reply_msg_len,
	                     tvb, off);
	
	return off;
}

static
guint c_dissect_msg_osd_map(proto_tree *root,
                           tvbuff_t *tvb,
                           guint front_len, guint middle_len _U_, guint data_len _U_,
                           c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint32 i;
	
	/* ceph:/src/messages/MOSDMap.h */
	
	//@TODO: Dissect map data.
	
	c_set_type(data, "OSD Map");
	
	ti = proto_tree_add_item(root, hf_msg_osd_map,
	                         tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_osd_map);
	
	proto_tree_add_item(tree, hf_msg_osd_map_fsid,
	                    tvb, off, 16, ENC_LITTLE_ENDIAN);
	off += 16;
	
	/*** Incremental Items ***/
	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_osd_map_inc_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	proto_item_append_text(data->item_root, ", Incremental Items: %u", i);
	
	off += 4;
	while (i--)
	{
		ti = proto_tree_add_item(tree, hf_msg_osd_map_inc,
		                         tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, hf_msg_osd_map_inc);
		
		proto_tree_add_item(subtree, hf_msg_osd_map_epoch,
		                    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
		off = c_dissect_blob(subtree, hf_msg_osd_map_data, hf_msg_osd_map_data_len,
		                     tvb, off);
		
		proto_item_set_end(ti, tvb, off);
	}
	
	/*** Non-incremental Items ***/
	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_osd_map_map_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	proto_item_append_text(data->item_root, ", Items: %u", i);
	off += 4;
	while (i--)
	{
		ti = proto_tree_add_item(tree, hf_msg_osd_map_map,
		                         tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, hf_msg_osd_map_map);
		
		proto_tree_add_item(subtree, hf_msg_osd_map_epoch,
		                    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
		off = c_dissect_blob(subtree, hf_msg_osd_map_data, hf_msg_osd_map_data_len,
		                     tvb, off);
		
		proto_item_set_end(ti, tvb, off);
	}
	
	if (data->header.ver >= 2)
	{
		proto_tree_add_item(tree, hf_msg_osd_map_oldest,
		                    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
		proto_tree_add_item(tree, hf_msg_osd_map_newest,
		                    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}
	
	return off;
}

static
guint c_dissect_msg_mon_cmd(proto_tree *root,
                          tvbuff_t *tvb,
                          guint front_len, guint middle_len _U_, guint data_len _U_,
                          c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint i;
	c_str str;
	
	/* ceph:/src/messages/MMonCommand.h */
	
	c_set_type(data, "Mon Command");
	
	off = c_dissect_paxos(root, tvb, off, data);
	
	ti = proto_tree_add_item(root, hf_msg_mon_cmd,
	                         tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_mon_cmd);
	
	proto_tree_add_item(tree, hf_msg_mon_cmd_fsid,
	                    tvb, off, 16, ENC_LITTLE_ENDIAN);
	off += 16;
	
	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_cmd_arg_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	while (i--)
	{
		ti = proto_tree_add_item(tree, hf_msg_mon_cmd_arg,
		                         tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, hf_msg_mon_cmd_arg);
		
		off = c_dissect_str(subtree, hf_msg_mon_cmd_str, &str, tvb, off);
		
		proto_item_append_text(ti, " %s", str.str);
		
		proto_item_set_end(ti, tvb, off);
	}
	
	return off;
}

static
guint c_dissect_msg_mon_cmd_ack(proto_tree *root,
                               tvbuff_t *tvb,
                               guint front_len, guint middle_len _U_, guint data_len,
                               c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint i;
	
	/* ceph:/src/messages/MMonCommandAck.h */
	
	c_set_type(data, "Mon Command Result");
	
	off = c_dissect_paxos(root, tvb, off, data);
	
	ti = proto_tree_add_item(root, hf_msg_mon_cmd_ack,
	                         tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_mon_cmd_ack);
	
	proto_tree_add_item(tree, hf_msg_mon_cmd_ack_code,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	off = c_dissect_blob(tree, hf_msg_mon_cmd_ack_res, hf_msg_mon_cmd_ack_res_len,
	                     tvb, off);
	
	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_cmd_ack_arg_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	while (i--)
	{
		ti = proto_tree_add_item(tree, hf_msg_mon_cmd_ack_arg,
		                         tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, hf_msg_mon_cmd_ack_arg);
		
		off = c_dissect_blob(subtree, hf_msg_mon_cmd_ack_arg_str,
		                     hf_msg_mon_cmd_ack_arg_str_len,
		                     tvb, off);
		
		proto_item_set_end(ti, tvb, off);
	}
	
	proto_tree_add_item(tree, hf_msg_mon_cmd_ack_data,
	                    tvb, front_len, data_len, ENC_NA);
	
	return front_len+data_len;
}

/*** MSGR Dissectors ***/

enum c_size_msg {
	C_OFF_HEAD0  = 0,
	C_SIZE_HEAD0 = (64+64+16+16+16)/8,
	
	C_OFF_HEAD1  = C_SIZE_HEAD0,
	C_SIZE_HEAD1 = (32+32+32+16)/8,
	
	C_OFF_HEAD2  = C_OFF_HEAD1 + C_SIZE_HEAD1 + C_SIZE_ENTITY_NAME,
	C_SIZE_HEAD2 = (16+16+32)/8,
	
	C_SIZE_HEAD = C_OFF_HEAD2 + C_SIZE_HEAD2,
	
	C_SIZE_FOOT = (32+32+32+64+8)/8
};

/** Dissect a MSG message.
 * 
 * These are Ceph's business messages and are generally sent to specific
 * node types.
 */
static
guint c_dissect_msg(proto_tree *tree,
                    tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	tvbuff_t *subtvb;
	proto_item *ti;
	proto_tree *subtree;
	guint16 type;
	guint32 front_len, middle_len, data_len;
	guint size, parsedsize;
	
	if (!tvb_bytes_exist(tvb, off, C_OFF_HEAD1 + C_SIZE_HEAD1))
		return C_NEEDMORE;
	
	front_len  = tvb_get_letoh64(tvb, off + C_OFF_HEAD1 + 0);
	middle_len = tvb_get_letoh64(tvb, off + C_OFF_HEAD1 + 4);
	data_len   = tvb_get_letoh64(tvb, off + C_OFF_HEAD1 + 8);
	
	size = C_SIZE_HEAD+front_len+middle_len+data_len+C_SIZE_FOOT;
	if (!tvb_bytes_exist(tvb, off, size))
		return off+size; /* We need more data to dissect. */
	
	/*** Header ***/
	
	/* @TODO: Old Header. */
	
	/* From ceph:/src/include/msgr.h
	struct ceph_msg_header {
		__le64 seq;       // message seq# for this session
		__le64 tid;       // transaction id
		__le16 type;      // message type
		__le16 priority;  // priority.  higher value == higher priority
		__le16 version;   // version of message encoding
		
		__le32 front_len; // bytes in main payload
		__le32 middle_len;// bytes in middle payload
		__le32 data_len;  // bytes of data payload
		__le16 data_off;  // sender: include full offset; receiver: mask against ~PAGE_MASK
		
		struct ceph_entity_name src;
		
		// oldest code we think can decode this.  unknown if zero.
		__le16 compat_version;
		__le16 reserved;
		__le32 crc; // header crc32c
	} __attribute__ ((packed));
	*/
	
	ti = proto_tree_add_item(tree, hf_head, tvb,
	                         off, C_SIZE_HEAD,
	                         ENC_NA);
	subtree = proto_item_add_subtree(ti, hf_head);
	
	data->header.seq = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(subtree, hf_head_seq,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	data->header.tid = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(subtree, hf_head_tid,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	data->header.type = type = tvb_get_letohs(tvb, off);
	proto_tree_add_item(subtree, hf_head_type,
	                    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	
	data->header.priority = tvb_get_letohs(tvb, off);
	proto_tree_add_item(subtree, hf_head_priority,
	                    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	data->header.ver = tvb_get_letohs(tvb, off);
	proto_tree_add_item(subtree, hf_head_version,
	                    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	
	proto_tree_add_item(subtree, hf_head_front_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_head_middle_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_head_data_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_head_data_off,
	                    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	
	off = c_dissect_entity_name(subtree, tvb, off, data);
	
	proto_tree_add_item(subtree, hf_head_compat_version,
	                    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	proto_tree_add_item(subtree, hf_head_reserved,
	                    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	proto_tree_add_item(subtree, hf_head_crc,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	proto_item_append_text(ti, ", Type: %s",
	                       val_to_str_ext(type, &c_msg_type_strings_ext, "Unknown (%04x)"));
	if (front_len ) proto_item_append_text(ti, ", Front Len: %d", front_len);
	if (middle_len) proto_item_append_text(ti, ", Mid Len: %d",   middle_len);
	if (data_len  ) proto_item_append_text(ti, ", Data Len: %d",  data_len);
	
	/*** Body ***/
	
	subtvb = tvb_new_subset_length(tvb, off, front_len+middle_len+data_len);
	
	switch (type)
	{
#define C_CALL_MSG(name) name(tree, \
                            subtvb, front_len, middle_len, data_len, data)
#define C_HANDLE_MSG(tag, name) case tag: parsedsize = C_CALL_MSG(name); break;
	
	C_HANDLE_MSG(C_CEPH_MSG_MON_MAP,           c_dissect_msg_mon_map)
	C_HANDLE_MSG(C_CEPH_MSG_MON_SUBSCRIBE,     c_dissect_msg_mon_sub)
	C_HANDLE_MSG(C_CEPH_MSG_MON_SUBSCRIBE_ACK, c_dissect_msg_mon_sub_ack)
	C_HANDLE_MSG(C_CEPH_MSG_AUTH,              c_dissect_msg_auth)
	C_HANDLE_MSG(C_CEPH_MSG_AUTH_REPLY,        c_dissect_msg_auth_reply)
	C_HANDLE_MSG(C_CEPH_MSG_OSD_MAP,           c_dissect_msg_osd_map)
	C_HANDLE_MSG(C_MSG_MON_COMMAND,            c_dissect_msg_mon_cmd)
	C_HANDLE_MSG(C_MSG_MON_COMMAND_ACK,        c_dissect_msg_mon_cmd_ack)
	
	default:
		parsedsize = C_CALL_MSG(c_dissect_msg_unknown);
#undef C_CALL_MSG
#undef C_HANDLE_MSG
	}
	off += front_len + middle_len + data_len;
	
	//@TODO: Warn if parsedsize != size of data in the packet.
	
	/*** Footer ***/
	
	/* @TODO: Old Footer. */
	
	/* From ceph:/src/include/msgr.h
	struct ceph_msg_footer {
		__le32 front_crc, middle_crc, data_crc;
		// sig holds the 64 bits of the digital signature for the message PLR
		__le64  sig;
		__u8 flags;
	} __attribute__ ((packed));
	*/
	
	ti = proto_tree_add_item(tree, hf_foot, tvb,
	                         off, C_SIZE_FOOT,
	                         ENC_NA);
	subtree = proto_item_add_subtree(ti, hf_foot);
	
	proto_tree_add_item(subtree, hf_foot_front_crc,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_foot_middle_crc,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_foot_data_crc,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	proto_tree_add_item(subtree, hf_foot_signature,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	off = c_dissect_flags(subtree, tvb, off, data); /* @HELP: Can we do this? */
	
	return off;
}

enum c_sizes_connect {
	C_SIZE_CONNECT = 33,
	C_SIZE_CONNECT_REPLY = 25,
	C_SIZE_HELLO_S = 2*C_SIZE_ENTITY_ADDR,
	C_SIZE_HELLO_C = C_SIZE_ENTITY_ADDR + C_SIZE_CONNECT
};

static
guint c_dissect_connect(proto_tree *root,
                        tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	/* From ceph:/src/include/msgr.h
	struct ceph_msg_connect {
		__le64 features;
		__le32 host_type;
		__le32 global_seq;
		__le32 connect_seq;
		__le32 protocol_version;
		__le32 authorizer_protocol;
		__le32 authorizer_len;
		__u8  flags;
	} __attribute__(packed);
	*/
	
	proto_item *ti;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, hf_connect, tvb,
	                         off, C_SIZE_CONNECT,
	                         ENC_NA);
	tree = proto_item_add_subtree(ti, hf_connect);
	
	off = c_dissect_features(tree, tvb, off, data);
	
	proto_tree_add_item(tree, hf_connect_host_type,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_seq_global,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_seq,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_proto_ver,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_auth_proto,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_auth_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	off = c_dissect_flags(tree, tvb, off, data);
	
	return off;
}

static
guint c_dissect_connect_reply(proto_tree *root,
                              tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	/* From ceph:/src/include/msgr.h
	struct ceph_msg_connect_reply {
		__u8 tag; // Handled outside.
		__le64 features;
		__le32 global_seq;
		__le32 connect_seq;
		__le32 protocol_version;
		__le32 authorizer_len;
		__u8 flags;
	} __attribute__ ((packed));
	*/
	
	proto_item *ti;
	proto_tree *tree;
	
	if (!tvb_bytes_exist(tvb, off, C_SIZE_CONNECT_REPLY))
		return off+C_SIZE_CONNECT_REPLY; /* We need more data to dissect. */
	
	c_set_type(data, "Connect Reply");
	
	ti = proto_tree_add_item(root, hf_connect_reply, tvb,
	                         off, C_SIZE_CONNECT_REPLY,
	                         ENC_NA);
	tree = proto_item_add_subtree(ti, hf_connect_reply);
	
	off = c_dissect_features(tree, tvb, off, data);
	
	proto_tree_add_item(tree, hf_connect_seq_global,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_seq,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_proto_ver,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_auth_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	off = c_dissect_flags(tree, tvb, off, data);
	
	return off;
}

/** Do the connection initiation dance.
 * 
 * This handles the data that is sent before the protocol is actually started.
 */
static
guint c_dissect_new(proto_tree *tree,
                  tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	gint banlen;
	guint size;
	
	/*
		Since the packet is larger than the max banner length we can read it
		all in safely.
	*/
	G_STATIC_ASSERT(C_BANNER_LEN_MAX+1 <= C_BANNER_LEN_MIN+C_SIZE_HELLO_C);
	G_STATIC_ASSERT(C_BANNER_LEN_MAX+1 <= C_BANNER_LEN_MIN+C_SIZE_HELLO_S);
	
	if (!tvb_bytes_exist(tvb, off, C_BANNER_LEN_MAX+1))
		return C_NEEDMORE;
	
	/* @TODO: handle invalid banners.
	if (tvb_memeql(tvb, off, C_BANNER, C_BANNER_LEN_MIN) != 0)
		return 0; // Invalid banner.
	*/
	
	banlen = tvb_strnlen(tvb, off, C_BANNER_LEN_MAX+1);
	/*
	if (banlen == -1)
		return 0; // Invalid banner.
	*/
	
	proto_tree_add_item(tree, hf_version, tvb, off, banlen, ENC_NA);
	off += banlen;
	
	size = c_from_server(data)? C_SIZE_HELLO_S : C_SIZE_HELLO_C;
	if (!tvb_bytes_exist(tvb, off, size))
		return off+size; /* We need more data to dissect. */
	
	c_set_type(data, "Connect");
	
	if (c_from_server(data))
		off = c_dissect_entity_addr(tree, hf_server_info, tvb, off, data);
	
	off = c_dissect_entity_addr(tree, hf_client_info, tvb, off, data);
	
	if (c_from_client(data))
		off = c_dissect_connect(tree, tvb, off, data);
	
	data->src->state = C_STATE_OPEN;
	
	return off;
}

/* Dissect a MSGR message.
 * 
 * MSGR is Ceph's outer message protocol.
 */
static
guint c_dissect_msgr(proto_tree *tree,
                   tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	guint8 tag;
	
	if (!tvb_bytes_exist(tvb, off, 1))
		return C_NEEDMORE;
	
	tag = tvb_get_guint8(tvb, off);
	proto_tree_add_item(tree, hf_tag, tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;
	
	switch (tag)
	{
	case C_TAG_READY:
	case C_TAG_RESETSESSION:
	case C_TAG_WAIT:
	case C_TAG_RETRY_SESSION:
	case C_TAG_RETRY_GLOBAL:
	case C_TAG_BADPROTOVER:
	case C_TAG_BADAUTHORIZER:
	case C_TAG_FEATURES:
		off = c_dissect_connect_reply(tree, tvb, off, data);
		break;
	case C_TAG_SEQ:
		if (!tvb_bytes_exist(tvb, off, C_SIZE_CONNECT_REPLY+8))
			return off+C_SIZE_CONNECT_REPLY+8; /* We need more data to dissect. */
		
		off = c_dissect_connect_reply(tree, tvb, off, data);
		off += 8; //@TODO: Read sequence number.
		break;
	case C_TAG_CLOSE:
		c_set_type(data, "CLOSE");
		data->src->state = C_STATE_NEW;
		break;
	case C_TAG_MSG:
		off = c_dissect_msg(tree, tvb, off, data);
		break;
	case C_TAG_ACK:
		c_set_type(data, "ACK");
		if (!tvb_bytes_exist(tvb, off, 8))
			return off+8; /* We need more data to dissect. */
		
		proto_item_append_text(data->item_root, ", Seq: %u",
		                       tvb_get_letohl(tvb, off));
		proto_tree_add_item(tree, hf_ack,
		                    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		break;
	case C_TAG_KEEPALIVE:
		c_set_type(data, "KEEPALIVE");
		/* No data. */
		break;
	case C_TAG_KEEPALIVE2:
	case C_TAG_KEEPALIVE2_ACK:
		if (!tvb_bytes_exist(tvb, off, C_SIZE_TIMESPEC))
			return off+C_SIZE_TIMESPEC; /* We need more data to dissect. */
		
		c_set_type(data, "KEEPALIVE2");
		off = c_dissect_timespec(tree, tvb, off, data);
		break;
	default:
		/*
			The default is to do nothing.  We have no way of knowing how
			long an unknown message will be.  Our best bet is to read
			just the tag (which we did above) and try to interpret the
			next byte as a message.  In the best case we step through
			the unknown message and when we hit the next known message
			we can continue.
			
			Stepping through byte-by-byte is slow, and creates a lot of
			"Unkown Tag" items (where only the first one is really
			meaningful) but we don't want to miss the next message if we
			can help it.
			
			Worst case is the message contains a byte that we think is a
			message.  In this case we will interpret garbage from there
			creating bogus items in the dissection results.  After we
			"dissect" that "PDU" we go back to the start and hope we get
			lucky and find ourselves realigned.
		*/
		c_set_type(data, "UNKNOWN");
		proto_item_append_text(data->item_root, ", Tag: %x", tag);
		//@TODO: Add expert info to allow filtering.
	}
	
	return off;
}

/* Dissect a Protocol Data Unit
 */
static
guint c_dissect_pdu(proto_tree *root,
                  tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, proto_ceph, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_ceph);
	
	data->item_root = ti;
	
	if (data->src->state == C_STATE_NEW)
		off = c_dissect_new(tree, tvb, off, data);
	else
		off = c_dissect_msgr(tree, tvb, off, data);
	
	proto_item_set_end(ti, tvb, off);
	return off;
}

static
int dissect_ceph(tvbuff_t *tvb, packet_info *pinfo,
                 proto_tree *tree, void *pdata _U_)
{
	guint off, offt;
	c_pkt_data data;
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ceph");
	col_clear(pinfo->cinfo, COL_INFO);
	
	off = 0;
	while (off < tvb_reported_length(tvb))
	{
		col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", "");
		col_set_fence(pinfo->cinfo, COL_INFO);
		c_pkt_data_init(&data, pinfo, off);
		
		offt = c_dissect_pdu(tree, tvb, off, &data);
		if (offt == 0) /* Need more data to determine PDU length. */
		{
			pinfo->desegment_offset = off;
			pinfo->desegment_len    = DESEGMENT_ONE_MORE_SEGMENT;
			return 1;
		}
		if (offt > tvb_reported_length(tvb)) /* Know PDU length, get rest */
		{
			pinfo->desegment_offset = off;
			pinfo->desegment_len    = offt - tvb_reported_length(tvb);
			return 1;
		}
		
		off = offt;
	}
	
	return off; // Perfect Fit.
}

/** An old style dissector proxy.
 * 
 * Proxies the old style dissector interface to the new style.
 */
static
void dissect_ceph_old(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ceph(tvb, pinfo, tree, NULL);
}

static
gboolean dissect_ceph_heur(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, void *data _U_)
{
	conversation_t *conv;
	
	if (tvb_reported_length(tvb) < C_BANNER_LEN_MIN)         return 0;
	if (tvb_memeql(tvb, 0, C_BANNER, C_BANNER_LEN_MIN) != 0) return 0;
	
	/*** It's ours! ***/
	
	conv = find_or_create_conversation(pinfo);
	/* Mark it as ours. */
	conversation_set_dissector(conv, ceph_handle);
	
	dissect_ceph(tvb, pinfo, tree, data);
	return 1;
}

/* Register the protocol with Wireshark.
 */
void
proto_register_ceph(void)
{
	//module_t *ceph_module;
	//expert_module_t* expert_ceph;
	
	static hf_register_info hf[] = {
		{ &hf_node_id, {
			"ID", "ceph.node_id",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The numeric ID of the node.", HFILL
		} },
		{ &hf_node_type, {
			"Source Node Type", "ceph.node_type",
			FT_UINT8, BASE_HEX, VALS(c_node_type_strings), 0,
			"The type of source node.", HFILL
		} },
		{ &hf_node_nonce, {
			"Nonce", "ceph.node_nonce",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Meaningless number to differentiate between nodes on the same system.", HFILL
		} },
		{ &hf_node_name, {
			"Source Name", "ceph.node",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_version, {
			"Version", "ceph.ver",
			FT_STRINGZ, BASE_NONE, NULL, 0,
			"The protocol version string.", HFILL
		} },
		{ &hf_client_info, {
			"Client's Identity", "ceph.client_info",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_server_info, {
			"Server's Identity", "ceph.server_info",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_sockaddr, {
			"Network Address", "ceph.sockaddr",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_inet_family, {
			"Address Family", "ceph.af",
			FT_UINT16, BASE_HEX, VALS(c_inet_strings), 0,
			"The address family of the client as seen by the server.", HFILL
		} },
		{ &hf_port, {
			"Port", "ceph.client.port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"The port of the client as seen by the server.", HFILL
		} },
		{ &hf_addr_ipv4, {
			"IPv4 Address", "ceph.client.ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"The IP address of the client as seen by the server.", HFILL
		} },
		{ &hf_addr_ipv6, {
			"IPv6 Address", "ceph.client.ip",
			FT_IPv6, BASE_NONE, NULL, 0,
			"The IP address of the client as seen by the server.", HFILL
		} },
		{ &hf_blob_data, {
			"Data", "ceph.blob.size",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_blob_size, {
			"Size", "ceph.blob.size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_string_data, {
			"Data", "ceph.string.size",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_string_size, {
			"Size", "ceph.string.size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_time, {
			"Timestamp", "ceph.time",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_time_sec, {
			"Seconds", "ceph.seconds",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_time_nsec, {
			"Nanoseconds", "ceph.nanoseconds",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_connect, {
			"Connection Negotiation", "ceph.connect",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_features, {
			"Features", "ceph.connect.features",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_features_low, {
			"Features", "ceph.connect.features.low",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_features_high, {
			"Features", "ceph.connect.features.high",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_feature_uid, {
			"UID", "ceph.features.uid",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_UID,
			NULL, HFILL
		} },
		{ &hf_feature_nosrcaddr, {
			"NOSRCADDR", "ceph.features.nosrcaddr",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_NOSRCADDR,
			NULL, HFILL
		} },
		{ &hf_feature_monclockcheck, {
			"MONCLOCKCHECK", "ceph.features.monclockcheck",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MONCLOCKCHECK,
			NULL, HFILL
		} },
		{ &hf_feature_flock, {
			"FLOCK", "ceph.features.flock",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_FLOCK,
			NULL, HFILL
		} },
		{ &hf_feature_subscribe2, {
			"SUBSCRIBE2", "ceph.features.subscribe2",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_SUBSCRIBE2,
			NULL, HFILL
		} },
		{ &hf_feature_monnames, {
			"MONNAMES", "ceph.features.monnames",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MONNAMES,
			NULL, HFILL
		} },
		{ &hf_feature_reconnect_seq, {
			"RECONNECT_SEQ", "ceph.features.reconnect_seq",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_RECONNECT_SEQ,
			NULL, HFILL
		} },
		{ &hf_feature_dirlayouthash, {
			"DIRLAYOUTHASH", "ceph.features.dirlayouthash",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_DIRLAYOUTHASH,
			NULL, HFILL
		} },
		{ &hf_feature_objectlocator, {
			"OBJECTLOCATOR", "ceph.features.objectlocator",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OBJECTLOCATOR,
			NULL, HFILL
		} },
		{ &hf_feature_pgid64, {
			"PGID64", "ceph.features.pgid64",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_PGID64,
			NULL, HFILL
		} },
		{ &hf_feature_incsubosdmap, {
			"INCSUBOSDMAP", "ceph.features.incsubosdmap",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_INCSUBOSDMAP,
			NULL, HFILL
		} },
		{ &hf_feature_pgpool3, {
			"PGPOOL3", "ceph.features.pgpool3",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_PGPOOL3,
			NULL, HFILL
		} },
		{ &hf_feature_osdreplymux, {
			"OSDREPLYMUX", "ceph.features.osdreplymux",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSDREPLYMUX,
			NULL, HFILL
		} },
		{ &hf_feature_osdenc, {
			"OSDENC", "ceph.features.osdenc",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSDENC,
			NULL, HFILL
		} },
		{ &hf_feature_omap, {
			"OMAP", "ceph.features.omap",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OMAP,
			NULL, HFILL
		} },
		{ &hf_feature_monenc, {
			"MONENC", "ceph.features.monenc",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MONENC,
			NULL, HFILL
		} },
		{ &hf_feature_query_t, {
			"QUERY_T", "ceph.features.query_t",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_QUERY_T,
			NULL, HFILL
		} },
		{ &hf_feature_indep_pg_map, {
			"INDEP_PG_MAP", "ceph.features.indep_pg_map",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_INDEP_PG_MAP,
			NULL, HFILL
		} },
		{ &hf_feature_crush_tunables, {
			"CRUSH_TUNABLES", "ceph.features.crush_tunables",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CRUSH_TUNABLES,
			NULL, HFILL
		} },
		{ &hf_feature_chunky_scrub, {
			"CHUNKY_SCRUB", "ceph.features.chunky_scrub",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CHUNKY_SCRUB,
			NULL, HFILL
		} },
		{ &hf_feature_mon_nullroute, {
			"MON_NULLROUTE", "ceph.features.mon_nullroute",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MON_NULLROUTE,
			NULL, HFILL
		} },
		{ &hf_feature_mon_gv, {
			"MON_GV", "ceph.features.mon_gv",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MON_GV,
			NULL, HFILL
		} },
		{ &hf_feature_backfill_reservation, {
			"BACKFILL_RESERVATION", "ceph.features.backfill_reservation",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_BACKFILL_RESERVATION,
			NULL, HFILL
		} },
		{ &hf_feature_msg_auth, {
			"MSG_AUTH", "ceph.features.msg_auth",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MSG_AUTH,
			NULL, HFILL
		} },
		{ &hf_feature_recovery_reservation, {
			"RECOVERY_RESERVATION", "ceph.features.recovery_reservation",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_RECOVERY_RESERVATION,
			NULL, HFILL
		} },
		{ &hf_feature_crush_tunables2, {
			"CRUSH_TUNABLES2", "ceph.features.crush_tunables2",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CRUSH_TUNABLES2,
			NULL, HFILL
		} },
		{ &hf_feature_createpoolid, {
			"CREATEPOOLID", "ceph.features.createpoolid",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CREATEPOOLID,
			NULL, HFILL
		} },
		{ &hf_feature_reply_create_inode, {
			"REPLY_CREATE_INODE", "ceph.features.reply_create_inode",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_REPLY_CREATE_INODE,
			NULL, HFILL
		} },
		{ &hf_feature_osd_hbmsgs, {
			"OSD_HBMSGS", "ceph.features.osd_hbmsgs",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_HBMSGS,
			NULL, HFILL
		} },
		{ &hf_feature_mdsenc, {
			"MDSENC", "ceph.features.mdsenc",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MDSENC,
			NULL, HFILL
		} },
		{ &hf_feature_osdhashpspool, {
			"OSDHASHPSPOOL", "ceph.features.osdhashpspool",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSDHASHPSPOOL,
			NULL, HFILL
		} },
		{ &hf_feature_mon_single_paxos, {
			"MON_SINGLE_PAXOS", "ceph.features.mon_single_paxos",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MON_SINGLE_PAXOS,
			NULL, HFILL
		} },
		{ &hf_feature_osd_snapmapper, {
			"OSD_SNAPMAPPER", "ceph.features.osd_snapmapper",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_SNAPMAPPER,
			NULL, HFILL
		} },
		{ &hf_feature_mon_scrub, {
			"MON_SCRUB", "ceph.features.mon_scrub",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MON_SCRUB,
			NULL, HFILL
		} },
		{ &hf_feature_osd_packed_recovery, {
			"OSD_PACKED_RECOVERY", "ceph.features.osd_packed_recovery",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_PACKED_RECOVERY,
			NULL, HFILL
		} },
		{ &hf_feature_osd_cachepool, {
			"OSD_CACHEPOOL", "ceph.features.osd_cachepool",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_CACHEPOOL,
			NULL, HFILL
		} },
		{ &hf_feature_crush_v2, {
			"CRUSH_V2", "ceph.features.crush_v2",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CRUSH_V2,
			NULL, HFILL
		} },
		{ &hf_feature_export_peer, {
			"EXPORT_PEER", "ceph.features.export_peer",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_EXPORT_PEER,
			NULL, HFILL
		} },
		{ &hf_feature_osd_erasure_codes, {
			"OSD_ERASURE_CODES", "ceph.features.osd_erasure_codes",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_ERASURE_CODES,
			NULL, HFILL
		} },
		{ &hf_feature_osd_tmap2omap, {
			"OSD_TMAP2OMAP", "ceph.features.osd_tmap2omap",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_TMAP2OMAP,
			NULL, HFILL
		} },
		{ &hf_feature_osdmap_enc, {
			"OSDMAP_ENC", "ceph.features.osdmap_enc",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSDMAP_ENC,
			NULL, HFILL
		} },
		{ &hf_feature_mds_inline_data, {
			"MDS_INLINE_DATA", "ceph.features.mds_inline_data",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MDS_INLINE_DATA,
			NULL, HFILL
		} },
		{ &hf_feature_crush_tunables3, {
			"CRUSH_TUNABLES3", "ceph.features.crush_tunables3",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CRUSH_TUNABLES3,
			NULL, HFILL
		} },
		{ &hf_feature_osd_primary_affinity, {
			"OSD_PRIMARY_AFFINITY", "ceph.features.osd_primary_affinity",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_PRIMARY_AFFINITY,
			NULL, HFILL
		} },
		{ &hf_feature_msgr_keepalive2, {
			"MSGR_KEEPALIVE2", "ceph.features.msgr_keepalive2",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MSGR_KEEPALIVE2,
			NULL, HFILL
		} },
		{ &hf_feature_reserved, {
			"RESERVED", "ceph.features.reserved",
			FT_BOOLEAN, 32, TFS(&tfs_set_notset), C_FEATURE_RESERVED,
			NULL, HFILL
		} },
		{ &hf_connect_host_type, {
			"Host Type", "ceph.connect.host",
			FT_UINT32, BASE_HEX, VALS(c_node_type_strings), 0,
			"The type of host.", HFILL
		} },
		{ &hf_connect_seq_global, {
			"Global Sequence Number", "ceph.connect.global_seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The number of connections initiated by this host.", HFILL
		} },
		{ &hf_connect_seq, {
			"Sequence Number", "ceph.connect.seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The number of connections initiated this session.", HFILL
		} },
		{ &hf_connect_proto_ver, {
			"Protocol Version", "ceph.connect.ver",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The protocol version to use.", HFILL
		} },
		{ &hf_connect_auth_proto, {
			"Authentication Protocol", "ceph.connect.auth.proto",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The authentication protocol to use.", HFILL
		} },
		{ &hf_connect_auth_len, {
			"Authentication Length", "ceph.connect.auth.length",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The length of the authentication.", HFILL
		} },
		{ &hf_flags, {
			"Flags", "ceph.connect.flags",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_flag_lossy, {
			"Lossy", "ceph.flags.lossy",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), C_FLAG_LOSSY,
			"Messages may be safely dropped.", HFILL
		} },
		{ &hf_connect_reply, {
			"Connection Negotiation Reply", "ceph.connect_reply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_tag, {
			"Tag", "ceph.tag",
			FT_UINT8, BASE_HEX|BASE_EXT_STRING, VALS(&c_tag_strings_ext), 0,
			NULL, HFILL
		} },
		{ &hf_ack, {
			"Acknowledgment", "ceph.ack",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head, {
			"Message Header", "ceph.head",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_seq, {
			"Sequence Number", "ceph.seq",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_tid, {
			"Transaction ID", "ceph.tid",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_type, {
			"Type", "ceph.type",
			FT_UINT16, BASE_HEX|BASE_EXT_STRING, VALS(&c_msg_type_strings_ext), 0,
			"Message type.", HFILL
		} },
		{ &hf_head_priority, {
			"Priority", "ceph.priority",
			FT_UINT16, BASE_DEC, NULL, 0,
			"The priority of this message, higher the more urgent.", HFILL
		} },
		{ &hf_head_version, {
			"Version", "ceph.version",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_front_len, {
			"Front Length", "ceph.front_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_middle_len, {
			"Middle Length", "ceph.middle_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_data_len, {
			"Data Length", "ceph.data_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_data_off, {
			"Data Offset", "ceph.data_off",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_compat_version, {
			"Compatibility Version", "ceph.compat_version",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The oldest code that can probably decode this message.", HFILL
		} },
		{ &hf_head_reserved, {
			"Reserved", "ceph.reserved",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_crc, {
			"CRC Checksum", "ceph.crc",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot, {
			"Message Footer", "ceph.foot",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot_front_crc, {
			"Front Checksum", "ceph.foot.front_crc",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot_middle_crc, {
			"Middle Checksum", "ceph.foot.middle_crc",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot_data_crc, {
			"Data Checksum", "ceph.foot.data_crc",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot_signature, {
			"Signature", "ceph.foot.signature",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_front, {
			"Front", "ceph.front",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_middle, {
			"Middle", "ceph.mid",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_data, {
			"Data", "ceph.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_paxos, {
			"Paxos Message", "ceph.paxos",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_paxos_ver, {
			"Paxos Version", "ceph.data",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_paxos_mon, {
			"Mon", "ceph.paxos.mon",
			FT_INT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_paxos_mon_tid, {
			"Mon Transaction ID", "ceph.paxos.tid",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_map, {
			"Mon Map Message", "ceph.msg.mon_map",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_map_data, {
			"Payload", "ceph.msg.mon_map.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_map_data_len, {
			"Payload Length", "ceph.msg.mon_map.data_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub, {
			"Mon Subscribe Message", "ceph.msg.mon_sub",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_item, {
			"Subscription Item", "ceph.msg.mon_sub.item",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_item_len, {
			"Number of items", "ceph.msg.mon_sub.item_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_what, {
			"What", "ceph.msg.mon_sub.what",
			FT_STRING, BASE_NONE, NULL, 0,
			"What to subscribe to.", HFILL
		} },
		{ &hf_msg_mon_sub_what_len, {
			"What Length", "ceph.msg.mon_sub.what_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_start, {
			"Start Time", "ceph.msg.mon_sub.start",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_flags, {
			"Flags", "ceph.msg.mon_sub.flags",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_flags_onetime, {
			"One Time", "ceph.msg.mon_sub.flags.onetime",
			FT_BOOLEAN, 8, TFS(&tfs_yes_no), C_MON_SUB_FLAG_ONETIME,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_ack, {
			"Subscription Acknowledgment", "ceph.msg.mon_sub_ack",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_ack_interval, {
			"Interval", "ceph.msg.mon_sub_ack.interval",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_ack_fsid, {
			"FSID", "ceph.msg.mon_sub_ack.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth, {
			"Auth Message", "ceph.msg.auth",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_proto, {
			"Protocol", "ceph.msg.auth.proto",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_payload, {
			"Payload", "ceph.msg.auth.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_payload_len, {
			"Payload Length", "ceph.msg.auth.data_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_monmap_epoch, {
			"Monmap epoch", "ceph.msg.auth.monmap_epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply, {
			"Auth Reply Message", "ceph.msg.auth_reply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_proto, {
			"Protocol", "ceph.msg.auth_reply.proto",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_result, {
			"Result", "ceph.msg.auth_reply.result",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_global_id, {
			"Global ID", "ceph.msg.auth_reply.id",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_data, {
			"Data", "ceph.msg.auth_reply.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_data_len, {
			"Data Length", "ceph.msg.auth_reply.data_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_msg, {
			"Message", "ceph.msg.auth_reply.msg",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_msg_len, {
			"Message Length", "ceph.msg.auth_reply.msg_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map, {
			"OSD Map Message", "ceph.msg.osd_map",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_fsid, {
			"FSID", "ceph.msg.osd_map.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_inc, {
			"Incremental Map", "ceph.msg.osd_map.inc",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_inc_len, {
			"Incremental Map Count", "ceph.msg.osd_map.inc_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_map, {
			"Map", "ceph.msg.osd_map.map",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_map_len, {
			"Map Count", "ceph.msg.osd_map.map_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_epoch, {
			"Epoch", "ceph.msg.osd_map.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_data, {
			"Map Data", "ceph.msg.osd_map.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_data_len, {
			"Data Length", "ceph.msg.osd_map.data_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_oldest, {
			"Oldest Map", "ceph.msg.osd_map.oldest",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_newest, {
			"Newest Map", "ceph.msg.osd_map.newest",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd, {
			"Mon Command", "ceph.msg.mon_cmd",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_fsid, {
			"FSID", "ceph.msg.mon_cmd.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_arg, {
			"Argument", "ceph.msg.mon_cmd.arg",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_arg_len, {
			"Argument Count", "ceph.msg.mon_cmd.arg_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_str, {
			"String", "ceph.msg.mon_cmd.str",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_str_len, {
			"String Length", "ceph.msg.mon_cmd.str_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack, {
			"Mon Command Result", "ceph.msg.mon_cmd_ack",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_code, {
			"Result Code", "ceph.msg.mon_cmd_ack.code",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_res, {
			"Result String", "ceph.msg.mon_cmd_ack.result",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_res_len, {
			"String Length", "ceph.msg.mon_cmd_ack.result_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_arg, {
			"Argument", "ceph.msg.mon_cmd_ack.arg",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_arg_len, {
			"Argument Count", "ceph.msg.mon_cmd_ack.arg_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_arg_str, {
			"String", "ceph.msg.mon_cmd_ack.str",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_arg_str_len, {
			"String Length", "ceph.msg.mon_cmd_ack.str_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_data, {
			"Data", "ceph.msg.mon_cmd_ack.data",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
	};
	
	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ceph,
	};
	
	/* Register the protocol name and description */
	proto_ceph = proto_register_protocol("Ceph", "Ceph", "ceph");
	
	/* Required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_ceph, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	
	/*** Preferences ***/
	//ceph_module = prefs_register_protocol(proto_ceph, proto_reg_handoff_ceph);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_ceph(void)
{
	ceph_handle = create_dissector_handle(dissect_ceph_old, proto_ceph);
	
	heur_dissector_add("tcp", dissect_ceph_heur, proto_ceph);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * indent-tabs-mode: t
 * End:
 *
 * vi: set noexpandtab:
 * :noTabs=false:
 */
