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
static int hf_filter_data                  = -1;
static int hf_node_id                      = -1;
static int hf_node_type                    = -1;
static int hf_node_nonce                   = -1;
static int hf_node_name                    = -1;
static int hf_src_slug                     = -1;
static int hf_src_type                     = -1;
static int hf_dst_type                     = -1;
static int hf_dst_slug                     = -1;
static int hf_banner                      = -1;
static int hf_client_info                  = -1;
static int hf_server_info                  = -1;
static int hf_sockaddr                     = -1;
static int hf_inet_family                  = -1;
static int hf_port                         = -1;
static int hf_addr_ipv4                    = -1;
static int hf_addr_ipv6                    = -1;
static int hf_string_data                  = -1;
static int hf_string_size                  = -1;
static int hf_time                         = -1;
static int hf_time_sec                     = -1;
static int hf_time_nsec                    = -1;
static int hf_encoded_ver                    = -1;
static int hf_encoded_compat                    = -1;
static int hf_encoded_size                    = -1;
static int hf_version                    = -1;
static int hf_epoch                    = -1;
static int hf_pool                    = -1;
static int hf_key                    = -1;
static int hf_namespace                    = -1;
static int hf_hash                    = -1;
static int hf_pgid_ver         = -1;
static int hf_pgid_pool         = -1;
static int hf_pgid_seed         = -1;
static int hf_pgid_preferred     = -1;
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
static int hf_connect_auth                 = -1;
static int hf_flags                        = -1;
static int hf_flag_lossy                   = -1;
static int hf_osd_flags                    = -1;
static int hf_osd_flag_ack                 = -1;
static int hf_osd_flag_onnvram             = -1;
static int hf_osd_flag_ondisk              = -1;
static int hf_osd_flag_retry               = -1;
static int hf_osd_flag_read                = -1;
static int hf_osd_flag_write               = -1;
static int hf_osd_flag_ordersnap           = -1;
static int hf_osd_flag_peerstat_old        = -1;
static int hf_osd_flag_balance_reads       = -1;
static int hf_osd_flag_parallelexec        = -1;
static int hf_osd_flag_pgop                = -1;
static int hf_osd_flag_exec                = -1;
static int hf_osd_flag_exec_public         = -1;
static int hf_osd_flag_localize_reads      = -1;
static int hf_osd_flag_rwordered           = -1;
static int hf_osd_flag_ignore_cache        = -1;
static int hf_osd_flag_skiprwlocks         = -1;
static int hf_osd_flag_ignore_overlay      = -1;
static int hf_osd_flag_flush               = -1;
static int hf_osd_flag_map_snap_clone      = -1;
static int hf_osd_flag_enforce_snapc       = -1;
static int hf_osd_op_type       = -1;
static int hf_osd_op_data       = -1;
static int hf_osd_op_payload_len       = -1;
static int hf_osd_redirect_oloc       = -1;
static int hf_osd_redirect_obj       = -1;
static int hf_osd_redirect_osdinstr       = -1;
static int hf_osd_redirect_osdinstr_data       = -1;
static int hf_osd_redirect_osdinstr_len       = -1;
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
static int hf_msg_mon_map_data_data        = -1;
static int hf_msg_mon_map_data_len         = -1;
static int hf_msg_mon_sub                  = -1;
static int hf_msg_mon_sub_item             = -1;
static int hf_msg_mon_sub_item_len         = -1;
static int hf_msg_mon_sub_what             = -1;
static int hf_msg_mon_sub_start            = -1;
static int hf_msg_mon_sub_flags            = -1;
static int hf_msg_mon_sub_flags_onetime    = -1;
static int hf_msg_mon_sub_ack              = -1;
static int hf_msg_mon_sub_ack_interval     = -1;
static int hf_msg_mon_sub_ack_fsid         = -1;
static int hf_msg_auth                     = -1;
static int hf_msg_auth_proto               = -1;
static int hf_msg_auth_payload             = -1;
static int hf_msg_auth_payload_data        = -1;
static int hf_msg_auth_payload_len         = -1;
static int hf_msg_auth_monmap_epoch        = -1;
static int hf_msg_auth_reply               = -1;
static int hf_msg_auth_reply_proto         = -1;
static int hf_msg_auth_reply_result        = -1;
static int hf_msg_auth_reply_global_id     = -1;
static int hf_msg_auth_reply_data          = -1;
static int hf_msg_auth_reply_data_data     = -1;
static int hf_msg_auth_reply_data_len      = -1;
static int hf_msg_auth_reply_msg           = -1;
static int hf_msg_osd_map                  = -1;
static int hf_msg_osd_map_fsid             = -1;
static int hf_msg_osd_map_inc              = -1;
static int hf_msg_osd_map_inc_len          = -1;
static int hf_msg_osd_map_map              = -1;
static int hf_msg_osd_map_map_len          = -1;
static int hf_msg_osd_map_epoch            = -1;
static int hf_msg_osd_map_data             = -1;
static int hf_msg_osd_map_data_data        = -1;
static int hf_msg_osd_map_data_len         = -1;
static int hf_msg_osd_map_oldest           = -1;
static int hf_msg_osd_map_newest           = -1;
static int hf_msg_mon_cmd                  = -1;
static int hf_msg_mon_cmd_fsid             = -1;
static int hf_msg_mon_cmd_arg              = -1;
static int hf_msg_mon_cmd_arg_len          = -1;
static int hf_msg_mon_cmd_str              = -1;
static int hf_msg_mon_cmd_ack              = -1;
static int hf_msg_mon_cmd_ack_code         = -1;
static int hf_msg_mon_cmd_ack_res          = -1;
static int hf_msg_mon_cmd_ack_arg          = -1;
static int hf_msg_mon_cmd_ack_arg_len      = -1;
static int hf_msg_mon_cmd_ack_arg_str      = -1;
static int hf_msg_mon_cmd_ack_data         = -1;
static int hf_msg_osd_op                   = -1;
static int hf_msg_osd_op_client_inc        = -1;
static int hf_msg_osd_op_osdmap_epoch      = -1;
static int hf_msg_osd_op_flags             = -1;
static int hf_msg_osd_op_mtime             = -1;
static int hf_msg_osd_op_reassert_version  = -1;
static int hf_msg_osd_op_oloc              = -1;
static int hf_msg_osd_op_pgid              = -1;
static int hf_msg_osd_op_oid               = -1;
static int hf_msg_osd_op_ops_len           = -1;
static int hf_msg_osd_op_op                = -1;
static int hf_msg_osd_op_snap_id           = -1;
static int hf_msg_osd_op_snap_seq          = -1;
static int hf_msg_osd_op_snaps_len         = -1;
static int hf_msg_osd_op_snap             = -1;
static int hf_msg_osd_op_retry_attempt     = -1;
static int hf_msg_osd_op_payload     = -1;
static int hf_msg_osd_opreply                   = -1;
static int hf_msg_osd_opreply_oid                   = -1;
static int hf_msg_osd_opreply_pgid                   = -1;
static int hf_msg_osd_opreply_flags                   = -1;
static int hf_msg_osd_opreply_result                   = -1;
static int hf_msg_osd_opreply_bad_replay_ver                   = -1;
static int hf_msg_osd_opreply_osdmap_epoch                   = -1;
static int hf_msg_osd_opreply_ops_len                   = -1;
static int hf_msg_osd_opreply_op                   = -1;
static int hf_msg_osd_opreply_retry_attempt                   = -1;
static int hf_msg_osd_opreply_rval                   = -1;
static int hf_msg_osd_opreply_replay_ver                   = -1;
static int hf_msg_osd_opreply_user_ver                   = -1;
static int hf_msg_osd_opreply_redirect                   = -1;
static int hf_msg_osd_opreply_payload                   = -1;

/* @TODO: Remove before release.  Just for copying convenience.
static int hf_msg_                         = -1;
*/

/* Initialize the expert items. */
static expert_field ei_unused = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_ceph = -1;

static const guint8 *C_BANNER = (const guint8*)"ceph";
enum c_banner {
	C_BANNER_LEN_MIN = 4,
	C_BANNER_LEN_MAX = 30,
};

#define c_inet_strings_VALUE_STRING_LIST(V) \
	V(C_IPv4, 0x0002, "IPv4") \
	V(C_IPv6, 0x000A, "IPv6")

typedef VALUE_STRING_ENUM(c_inet_strings) c_inet;
VALUE_STRING_ARRAY(c_inet_strings);

static _U_
const char *c_inet_string(c_inet val)
{
	return val_to_str(val, c_inet_strings, "Unknown (0x%04x)");
}

/***** Feature Flags *****/
/* Transmuted from ceph:/src/include/ceph_features.h */
typedef enum _c_features {
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
} c_features;

/***** Connect Message Flags *****/
typedef enum _c_flags {
	C_FLAG_LOSSY = 1 << 0,
} c_flags;

/***** Message Tags *****/
#define c_tag_strings_VALUE_STRING_LIST(V) \
	V(C_TAG_READY,          0x01, "server->client: ready for messages")                  \
	V(C_TAG_RESETSESSION,   0x02, "server->client: reset, try again")                    \
	V(C_TAG_WAIT,           0x03, "server->client: wait for racing incoming connection") \
	V(C_TAG_RETRY_SESSION,  0x04, "server->client + cseq: try again with higher cseq")   \
	V(C_TAG_RETRY_GLOBAL,   0x05, "server->client + gseq: try again with higher gseq")   \
	V(C_TAG_CLOSE,          0x06, "closing pipe")                                        \
	V(C_TAG_MSG,            0x07, "message")                                             \
	V(C_TAG_ACK,            0x08, "message ack")                                         \
	V(C_TAG_KEEPALIVE,      0x09, "just a keepalive byte!")                              \
	V(C_TAG_BADPROTOVER,    0x0A, "bad protocol version")                                \
	V(C_TAG_BADAUTHORIZER,  0x0B, "bad authorizer")                                      \
	V(C_TAG_FEATURES,       0x0C, "insufficient features")                               \
	V(C_TAG_SEQ,            0x0D, "64-bit int follows with seen seq number")             \
	V(C_TAG_KEEPALIVE2,     0x0E, "keepalive2")                                          \
	V(C_TAG_KEEPALIVE2_ACK, 0x0F, "keepalive2 reply")                                    \

typedef VALUE_STRING_ENUM(c_tag_strings) c_tag;
VALUE_STRING_ARRAY(c_tag_strings);

static const
value_string_ext c_tag_strings_ext = VALUE_STRING_EXT_INIT(c_tag_strings);

static _U_
const char *c_tag_string(c_tag val)
{
	return val_to_str_ext(val, &c_tag_strings_ext, "Unknown (0x%02x)");
}

/* Extracted from the Ceph tree.
 * 
 * These are MSG_* constants for server <-> server (internal) messages. and
 * CEPH_MSG_* for client <-> server messages.  There is no functional
 * difference, just a naming convention.
 */
#define c_msg_type_strings_VALUE_STRING_LIST(V) \
	V(C_MSG_UNKNOWN,                     0x0000, "Unknown (0x0000)")                  \
	                                                                                  \
	V(C_CEPH_MSG_SHUTDOWN,               0x0001, "C_CEPH_MSG_SHUTDOWN")               \
	V(C_CEPH_MSG_PING,                   0x0002, "C_CEPH_MSG_PING")                   \
	V(C_CEPH_MSG_MON_MAP,                0x0004, "C_CEPH_MSG_MON_MAP")                \
	V(C_CEPH_MSG_MON_GET_MAP,            0x0005, "C_CEPH_MSG_MON_GET_MAP")            \
	V(C_CEPH_MSG_STATFS,                 0x000D, "C_CEPH_MSG_STATFS")                 \
	V(C_CEPH_MSG_STATFS_REPLY,           0x000E, "C_CEPH_MSG_STATFS_REPLY")           \
	V(C_CEPH_MSG_MON_SUBSCRIBE,          0x000F, "C_CEPH_MSG_MON_SUBSCRIBE")          \
	V(C_CEPH_MSG_MON_SUBSCRIBE_ACK,      0x0010, "C_CEPH_MSG_MON_SUBSCRIBE_ACK")      \
	V(C_CEPH_MSG_AUTH,                   0x0011, "C_CEPH_MSG_AUTH")                   \
	V(C_CEPH_MSG_AUTH_REPLY,             0x0012, "C_CEPH_MSG_AUTH_REPLY")             \
	V(C_CEPH_MSG_MON_GET_VERSION,        0x0013, "C_CEPH_MSG_MON_GET_VERSION")        \
	V(C_CEPH_MSG_MON_GET_VERSION_REPLY,  0x0014, "C_CEPH_MSG_MON_GET_VERSION_REPLY")  \
	V(C_CEPH_MSG_MDS_MAP,                0x0015, "C_CEPH_MSG_MDS_MAP")                \
	V(C_CEPH_MSG_CLIENT_SESSION,         0x0016, "C_CEPH_MSG_CLIENT_SESSION")         \
	V(C_CEPH_MSG_CLIENT_RECONNECT,       0x0017, "C_CEPH_MSG_CLIENT_RECONNECT")       \
	V(C_CEPH_MSG_CLIENT_REQUEST,         0x0018, "C_CEPH_MSG_CLIENT_REQUEST")         \
	V(C_CEPH_MSG_CLIENT_REQUEST_FORWARD, 0x0019, "C_CEPH_MSG_CLIENT_REQUEST_FORWARD") \
	V(C_CEPH_MSG_CLIENT_REPLY,           0x001A, "C_CEPH_MSG_CLIENT_REPLY")           \
	V(C_MSG_PAXOS,                       0x0028, "C_MSG_PAXOS")                       \
	V(C_CEPH_MSG_OSD_MAP,                0x0029, "C_CEPH_MSG_OSD_MAP")                \
	V(C_CEPH_MSG_OSD_OP,                 0x002A, "C_CEPH_MSG_OSD_OP")                 \
	V(C_CEPH_MSG_OSD_OPREPLY,            0x002B, "C_CEPH_MSG_OSD_OPREPLY")            \
	V(C_CEPH_MSG_WATCH_NOTIFY,           0x002C, "C_CEPH_MSG_WATCH_NOTIFY")           \
	V(C_MSG_FORWARD,                     0x002E, "C_MSG_FORWARD")                     \
	V(C_MSG_ROUTE,                       0x002F, "C_MSG_ROUTE")                       \
	V(C_MSG_POOLOPREPLY,                 0x0030, "C_MSG_POOLOPREPLY")                 \
	V(C_MSG_POOLOP,                      0x0031, "C_MSG_POOLOP")                      \
	V(C_MSG_MON_COMMAND,                 0x0032, "C_MSG_MON_COMMAND")                 \
	V(C_MSG_MON_COMMAND_ACK,             0x0033, "C_MSG_MON_COMMAND_ACK")             \
	V(C_MSG_LOG,                         0x0034, "C_MSG_LOG")                         \
	V(C_MSG_LOGACK,                      0x0035, "C_MSG_LOGACK")                      \
	V(C_MSG_MON_OBSERVE,                 0x0036, "C_MSG_MON_OBSERVE")                 \
	V(C_MSG_MON_OBSERVE_NOTIFY,          0x0037, "C_MSG_MON_OBSERVE_NOTIFY")          \
	V(C_MSG_CLASS,                       0x0038, "C_MSG_CLASS")                       \
	V(C_MSG_CLASS_ACK,                   0x0039, "C_MSG_CLASS_ACK")                   \
	V(C_MSG_GETPOOLSTATS,                0x003A, "C_MSG_GETPOOLSTATS")                \
	V(C_MSG_GETPOOLSTATSREPLY,           0x003B, "C_MSG_GETPOOLSTATSREPLY")           \
	V(C_MSG_MON_GLOBAL_ID,               0x003C, "C_MSG_MON_GLOBAL_ID")               \
	V(C_CEPH_MSG_PRIO_LOW,               0x0040, "C_CEPH_MSG_PRIO_LOW")               \
	V(C_MSG_MON_SCRUB,                   0x0040, "C_MSG_MON_SCRUB")                   \
	V(C_MSG_MON_ELECTION,                0x0041, "C_MSG_MON_ELECTION")                \
	V(C_MSG_MON_PAXOS,                   0x0042, "C_MSG_MON_PAXOS")                   \
	V(C_MSG_MON_PROBE,                   0x0043, "C_MSG_MON_PROBE")                   \
	V(C_MSG_MON_JOIN,                    0x0044, "C_MSG_MON_JOIN")                    \
	V(C_MSG_MON_SYNC,                    0x0045, "C_MSG_MON_SYNC")                    \
	V(C_MSG_OSD_PING,                    0x0046, "C_MSG_OSD_PING")                    \
	V(C_MSG_OSD_BOOT,                    0x0047, "C_MSG_OSD_BOOT")                    \
	V(C_MSG_OSD_FAILURE,                 0x0048, "C_MSG_OSD_FAILURE")                 \
	V(C_MSG_OSD_ALIVE,                   0x0049, "C_MSG_OSD_ALIVE")                   \
	V(C_MSG_OSD_MARK_ME_DOWN,            0x004A, "C_MSG_OSD_MARK_ME_DOWN")            \
	V(C_MSG_OSD_SUBOP,                   0x004C, "C_MSG_OSD_SUBOP")                   \
	V(C_MSG_OSD_SUBOPREPLY,              0x004D, "C_MSG_OSD_SUBOPREPLY")              \
	V(C_MSG_OSD_PGTEMP,                  0x004E, "C_MSG_OSD_PGTEMP")                  \
	V(C_MSG_OSD_PG_NOTIFY,               0x0050, "C_MSG_OSD_PG_NOTIFY")               \
	V(C_MSG_OSD_PG_QUERY,                0x0051, "C_MSG_OSD_PG_QUERY")                \
	V(C_MSG_OSD_PG_SUMMARY,              0x0052, "C_MSG_OSD_PG_SUMMARY")              \
	V(C_MSG_OSD_PG_LOG,                  0x0053, "C_MSG_OSD_PG_LOG")                  \
	V(C_MSG_OSD_PG_REMOVE,               0x0054, "C_MSG_OSD_PG_REMOVE")               \
	V(C_MSG_OSD_PG_INFO,                 0x0055, "C_MSG_OSD_PG_INFO")                 \
	V(C_MSG_OSD_PG_TRIM,                 0x0056, "C_MSG_OSD_PG_TRIM")                 \
	V(C_MSG_PGSTATS,                     0x0057, "C_MSG_PGSTATS")                     \
	V(C_MSG_PGSTATSACK,                  0x0058, "C_MSG_PGSTATSACK")                  \
	V(C_MSG_OSD_PG_CREATE,               0x0059, "C_MSG_OSD_PG_CREATE")               \
	V(C_MSG_REMOVE_SNAPS,                0x005A, "C_MSG_REMOVE_SNAPS")                \
	V(C_MSG_OSD_SCRUB,                   0x005B, "C_MSG_OSD_SCRUB")                   \
	V(C_MSG_OSD_PG_MISSING,              0x005C, "C_MSG_OSD_PG_MISSING")              \
	V(C_MSG_OSD_REP_SCRUB,               0x005D, "C_MSG_OSD_REP_SCRUB")               \
	V(C_MSG_OSD_PG_SCAN,                 0x005E, "C_MSG_OSD_PG_SCAN")                 \
	V(C_MSG_OSD_PG_BACKFILL,             0x005F, "C_MSG_OSD_PG_BACKFILL")             \
	V(C_MSG_COMMAND,                     0x0061, "C_MSG_COMMAND")                     \
	V(C_MSG_COMMAND_REPLY,               0x0062, "C_MSG_COMMAND_REPLY")               \
	V(C_MSG_OSD_BACKFILL_RESERVE,        0x0063, "C_MSG_OSD_BACKFILL_RESERVE")        \
	V(C_MSG_MDS_BEACON,                  0x0064, "C_MSG_MDS_BEACON")                  \
	V(C_MSG_MDS_SLAVE_REQUEST,           0x0065, "C_MSG_MDS_SLAVE_REQUEST")           \
	V(C_MSG_MDS_TABLE_REQUEST,           0x0066, "C_MSG_MDS_TABLE_REQUEST")           \
	V(C_MSG_OSD_PG_PUSH,                 0x0069, "C_MSG_OSD_PG_PUSH")                 \
	V(C_MSG_OSD_PG_PULL,                 0x006A, "C_MSG_OSD_PG_PULL")                 \
	V(C_MSG_OSD_PG_PUSH_REPLY,           0x006B, "C_MSG_OSD_PG_PUSH_REPLY")           \
	V(C_MSG_OSD_EC_WRITE,                0x006C, "C_MSG_OSD_EC_WRITE")                \
	V(C_MSG_OSD_EC_WRITE_REPLY,          0x006D, "C_MSG_OSD_EC_WRITE_REPLY")          \
	V(C_MSG_OSD_EC_READ,                 0x006E, "C_MSG_OSD_EC_READ")                 \
	V(C_MSG_OSD_EC_READ_REPLY,           0x006F, "C_MSG_OSD_EC_READ_REPLY")           \
	V(C_CEPH_MSG_PRIO_DEFAULT,           0x007F, "C_CEPH_MSG_PRIO_DEFAULT")           \
	V(C_MSG_OSD_RECOVERY_RESERVE,        0x0096, "C_MSG_OSD_RECOVERY_RESERVE")        \
	V(C_CEPH_MSG_PRIO_HIGH,              0x00C4, "C_CEPH_MSG_PRIO_HIGH")              \
	V(C_CEPH_MSG_PRIO_HIGHEST,           0x00FF, "C_CEPH_MSG_PRIO_HIGHEST")           \
	V(C_MSG_MDS_RESOLVE,                 0x0200, "C_MSG_MDS_RESOLVE")                 \
	V(C_MSG_MDS_RESOLVEACK,              0x0201, "C_MSG_MDS_RESOLVEACK")              \
	V(C_MSG_MDS_CACHEREJOIN,             0x0202, "C_MSG_MDS_CACHEREJOIN")             \
	V(C_MSG_MDS_DISCOVER,                0x0203, "C_MSG_MDS_DISCOVER")                \
	V(C_MSG_MDS_DISCOVERREPLY,           0x0204, "C_MSG_MDS_DISCOVERREPLY")           \
	V(C_MSG_MDS_INODEUPDATE,             0x0205, "C_MSG_MDS_INODEUPDATE")             \
	V(C_MSG_MDS_DIRUPDATE,               0x0206, "C_MSG_MDS_DIRUPDATE")               \
	V(C_MSG_MDS_CACHEEXPIRE,             0x0207, "C_MSG_MDS_CACHEEXPIRE")             \
	V(C_MSG_MDS_DENTRYUNLINK,            0x0208, "C_MSG_MDS_DENTRYUNLINK")            \
	V(C_MSG_MDS_FRAGMENTNOTIFY,          0x0209, "C_MSG_MDS_FRAGMENTNOTIFY")          \
	V(C_MSG_MDS_OFFLOAD_TARGETS,         0x020A, "C_MSG_MDS_OFFLOAD_TARGETS")         \
	V(C_MSG_MDS_DENTRYLINK,              0x020C, "C_MSG_MDS_DENTRYLINK")              \
	V(C_MSG_MDS_FINDINO,                 0x020D, "C_MSG_MDS_FINDINO")                 \
	V(C_MSG_MDS_FINDINOREPLY,            0x020E, "C_MSG_MDS_FINDINOREPLY")            \
	V(C_MSG_MDS_OPENINO,                 0x020F, "C_MSG_MDS_OPENINO")                 \
	V(C_MSG_MDS_OPENINOREPLY,            0x0210, "C_MSG_MDS_OPENINOREPLY")            \
	V(C_MSG_MDS_LOCK,                    0x0300, "C_MSG_MDS_LOCK")                    \
	V(C_MSG_MDS_INODEFILECAPS,           0x0301, "C_MSG_MDS_INODEFILECAPS")           \
	V(C_CEPH_MSG_CLIENT_CAPS,            0x0310, "C_CEPH_MSG_CLIENT_CAPS")            \
	V(C_CEPH_MSG_CLIENT_LEASE,           0x0311, "C_CEPH_MSG_CLIENT_LEASE")           \
	V(C_CEPH_MSG_CLIENT_SNAP,            0x0312, "C_CEPH_MSG_CLIENT_SNAP")            \
	V(C_CEPH_MSG_CLIENT_CAPRELEASE,      0x0313, "C_CEPH_MSG_CLIENT_CAPRELEASE")      \
	V(C_MSG_MDS_EXPORTDIRDISCOVER,       0x0449, "C_MSG_MDS_EXPORTDIRDISCOVER")       \
	V(C_MSG_MDS_EXPORTDIRDISCOVERACK,    0x0450, "C_MSG_MDS_EXPORTDIRDISCOVERACK")    \
	V(C_MSG_MDS_EXPORTDIRCANCEL,         0x0451, "C_MSG_MDS_EXPORTDIRCANCEL")         \
	V(C_MSG_MDS_EXPORTDIRPREP,           0x0452, "C_MSG_MDS_EXPORTDIRPREP")           \
	V(C_MSG_MDS_EXPORTDIRPREPACK,        0x0453, "C_MSG_MDS_EXPORTDIRPREPACK")        \
	V(C_MSG_MDS_EXPORTDIRWARNING,        0x0454, "C_MSG_MDS_EXPORTDIRWARNING")        \
	V(C_MSG_MDS_EXPORTDIRWARNINGACK,     0x0455, "C_MSG_MDS_EXPORTDIRWARNINGACK")     \
	V(C_MSG_MDS_EXPORTDIR,               0x0456, "C_MSG_MDS_EXPORTDIR")               \
	V(C_MSG_MDS_EXPORTDIRACK,            0x0457, "C_MSG_MDS_EXPORTDIRACK")            \
	V(C_MSG_MDS_EXPORTDIRNOTIFY,         0x0458, "C_MSG_MDS_EXPORTDIRNOTIFY")         \
	V(C_MSG_MDS_EXPORTDIRNOTIFYACK,      0x0459, "C_MSG_MDS_EXPORTDIRNOTIFYACK")      \
	V(C_MSG_MDS_EXPORTDIRFINISH,         0x0460, "C_MSG_MDS_EXPORTDIRFINISH")         \
	V(C_MSG_MDS_EXPORTCAPS,              0x0470, "C_MSG_MDS_EXPORTCAPS")              \
	V(C_MSG_MDS_EXPORTCAPSACK,           0x0471, "C_MSG_MDS_EXPORTCAPSACK")           \
	V(C_MSG_MDS_HEARTBEAT,               0x0500, "C_MSG_MDS_HEARTBEAT")               \
	V(C_MSG_TIMECHECK,                   0x0600, "C_MSG_TIMECHECK")                   \
	V(C_MSG_MON_HEALTH,                  0x0601, "C_MSG_MON_HEALTH")

typedef VALUE_STRING_ENUM(c_msg_type_strings) c_msg_type;
VALUE_STRING_ARRAY(c_msg_type_strings);

static const
value_string_ext c_msg_type_strings_ext = VALUE_STRING_EXT_INIT(c_msg_type_strings);

static
const char *c_msg_type_string(c_msg_type val)
{
	return val_to_str_ext(val, &c_msg_type_strings_ext, "Unknown (0x%04x)");
}

#define c_osd_optype_strings_VALUE_STRING_LIST(V) \
	/*** Raw Codes ***/                                                     \
	V(C_OSD_OP_MODE,       0xf000, "C_OSD_OP_MODE")                         \
	V(C_OSD_OP_MODE_RD,    0x1000, "C_OSD_OP_MODE_RD")                      \
	V(C_OSD_OP_MODE_WR,    0x2000, "C_OSD_OP_MODE_WR")                      \
	V(C_OSD_OP_MODE_RMW,   0x3000, "C_OSD_OP_MODE_RMW")                     \
	V(C_OSD_OP_MODE_SUB,   0x4000, "C_OSD_OP_MODE_SUB")                     \
	V(C_OSD_OP_MODE_CACHE, 0x8000, "C_OSD_OP_MODE_CACHE")                   \
	                                                                        \
	V(C_OSD_OP_TYPE,       0x0f00, "C_OSD_OP_TYPE")                         \
	V(C_OSD_OP_TYPE_LOCK,  0x0100, "C_OSD_OP_TYPE_LOCK")                    \
	V(C_OSD_OP_TYPE_DATA,  0x0200, "C_OSD_OP_TYPE_DATA")                    \
	V(C_OSD_OP_TYPE_ATTR,  0x0300, "C_OSD_OP_TYPE_ATTR")                    \
	V(C_OSD_OP_TYPE_EXEC,  0x0400, "C_OSD_OP_TYPE_EXEC")                    \
	V(C_OSD_OP_TYPE_PG,    0x0500, "C_OSD_OP_TYPE_PG")                      \
	V(C_OSD_OP_TYPE_MULTI, 0x0600, "C_OSD_OP_TYPE_MULTI") /* multiobject */ \
	                                                                        \
	/*** Sorted by value, keep it that way. ***/                            \
	V(C_OSD_OP_READ,                                                        \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x01,                     \
	  "C_OSD_OP_READ")                                                      \
	V(C_OSD_OP_STAT,                                                        \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x02,                     \
	  "C_OSD_OP_STAT")                                                      \
	V(C_OSD_OP_MAPEXT,                                                      \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x03,                     \
	  "C_OSD_OP_MAPEXT")                                                    \
	V(C_OSD_OP_MASKTRUNC,                                                   \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x04,                     \
	  "C_OSD_OP_MASKTRUNC")                                                 \
	V(C_OSD_OP_SPARSE_READ,                                                 \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x05,                     \
	  "C_OSD_OP_SPARSE_READ")                                               \
	V(C_OSD_OP_NOTIFY,                                                      \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x06,                     \
	  "C_OSD_OP_NOTIFY")                                                    \
	V(C_OSD_OP_NOTIFY_ACK,                                                  \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x07,                     \
	  "C_OSD_OP_NOTIFY_ACK")                                                \
	V(C_OSD_OP_ASSERT_VER,                                                  \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x08,                     \
	  "C_OSD_OP_ASSERT_VER")                                                \
	V(C_OSD_OP_LIST_WATCHERS,                                               \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x09,                     \
	  "C_OSD_OP_LIST_WATCHERS")                                             \
	V(C_OSD_OP_LIST_SNAPS,                                                  \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x0A,                     \
	  "C_OSD_OP_LIST_SNAPS")                                                \
	V(C_OSD_OP_SYNC_READ,                                                   \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x0B,                     \
	  "C_OSD_OP_SYNC_READ")                                                 \
	V(C_OSD_OP_TMAPGET,                                                     \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x0C,                     \
	  "C_OSD_OP_TMAPGET")                                                   \
	V(C_OSD_OP_OMAPGETKEYS,                                                 \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x11,                     \
	  "C_OSD_OP_OMAPGETKEYS")                                               \
	V(C_OSD_OP_OMAPGETVALS,                                                 \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x12,                     \
	  "C_OSD_OP_OMAPGETVALS")                                               \
	V(C_OSD_OP_OMAPGETHEADER,                                               \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x13,                     \
	  "C_OSD_OP_OMAPGETHEADER")                                             \
	V(C_OSD_OP_OMAPGETVALSBYKEYS,                                           \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x14,                     \
	  "C_OSD_OP_OMAPGETVALSBYKEYS")                                         \
	V(C_OSD_OP_OMAP_CMP,                                                    \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x19,                     \
	  "C_OSD_OP_OMAP_CMP")                                                  \
	V(C_OSD_OP_COPY_GET_CLASSIC,                                            \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x1B,                     \
	  "C_OSD_OP_COPY_GET_CLASSIC")                                          \
	V(C_OSD_OP_ISDIRTY,                                                     \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x1D,                     \
	  "C_OSD_OP_ISDIRTY")                                                   \
	V(C_OSD_OP_COPY_GET,                                                    \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_DATA  | 0x1E,                     \
	  "C_OSD_OP_COPY_GET")                                                  \
	V(C_OSD_OP_GETXATTR,                                                    \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_ATTR  | 0x01,                     \
	  "C_OSD_OP_GETXATTR")                                                  \
	V(C_OSD_OP_GETXATTRS,                                                   \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_ATTR  | 0x02,                     \
	  "C_OSD_OP_GETXATTRS")                                                 \
	V(C_OSD_OP_CMPXATTR,                                                    \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_ATTR  | 0x03,                     \
	  "C_OSD_OP_CMPXATTR")                                                  \
	V(C_OSD_OP_CALL,                                                        \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_EXEC  | 0x01,                     \
	  "C_OSD_OP_CALL")                                                      \
	V(C_OSD_OP_PGLS,                                                        \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_PG    | 0x01,                     \
	  "C_OSD_OP_PGLS")                                                      \
	V(C_OSD_OP_PGLS_FILTER,                                                 \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_PG    | 0x02,                     \
	  "C_OSD_OP_PGLS_FILTER")                                               \
	V(C_OSD_OP_PG_HITSET_LS,                                                \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_PG    | 0x03,                     \
	  "C_OSD_OP_PG_HITSET_LS")                                              \
	V(C_OSD_OP_PG_HITSET_GET,                                               \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_PG    | 0x04,                     \
	  "C_OSD_OP_PG_HITSET_GET")                                             \
	V(C_OSD_OP_ASSERT_SRC_VERSION,                                          \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_MULTI | 0x02,                     \
	  "C_OSD_OP_ASSERT_SRC_VERSION")                                        \
	V(C_OSD_OP_SRC_CMPXATTR,                                                \
	  C_OSD_OP_MODE_RD    | C_OSD_OP_TYPE_MULTI | 0x03,                     \
	  "C_OSD_OP_SRC_CMPXATTR")                                              \
	V(C_OSD_OP_WRLOCK,                                                      \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_LOCK  | 0x01,                     \
	  "C_OSD_OP_WRLOCK")                                                    \
	V(C_OSD_OP_WRUNLOCK,                                                    \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_LOCK  | 0x02,                     \
	  "C_OSD_OP_WRUNLOCK")                                                  \
	V(C_OSD_OP_RDLOCK,                                                      \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_LOCK  | 0x03,                     \
	  "C_OSD_OP_RDLOCK")                                                    \
	V(C_OSD_OP_RDUNLOCK,                                                    \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_LOCK  | 0x04,                     \
	  "C_OSD_OP_RDUNLOCK")                                                  \
	V(C_OSD_OP_UPLOCK,                                                      \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_LOCK  | 0x05,                     \
	  "C_OSD_OP_UPLOCK")                                                    \
	V(C_OSD_OP_DNLOCK,                                                      \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_LOCK  | 0x06,                     \
	  "C_OSD_OP_DNLOCK")                                                    \
	V(C_OSD_OP_WRITE,                                                       \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x01,                     \
	  "C_OSD_OP_WRITE")                                                     \
	V(C_OSD_OP_WRITEFULL,                                                   \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x02,                     \
	  "C_OSD_OP_WRITEFULL")                                                 \
	V(C_OSD_OP_TRUNCATE,                                                    \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x03,                     \
	  "C_OSD_OP_TRUNCATE")                                                  \
	V(C_OSD_OP_ZERO,                                                        \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x04,                     \
	  "C_OSD_OP_ZERO")                                                      \
	V(C_OSD_OP_DELETE,                                                      \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x05,                     \
	  "C_OSD_OP_DELETE")                                                    \
	V(C_OSD_OP_APPEND,                                                      \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x06,                     \
	  "C_OSD_OP_APPEND")                                                    \
	V(C_OSD_OP_STARTSYNC,                                                   \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x07,                     \
	  "C_OSD_OP_STARTSYNC")                                                 \
	V(C_OSD_OP_SETTRUNC,                                                    \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x08,                     \
	  "C_OSD_OP_SETTRUNC")                                                  \
	V(C_OSD_OP_TRIMTRUNC,                                                   \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x09,                     \
	  "C_OSD_OP_TRIMTRUNC")                                                 \
	V(C_OSD_OP_TMAPPUT,                                                     \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x0B,                     \
	  "C_OSD_OP_TMAPPUT")                                                   \
	V(C_OSD_OP_CREATE,                                                      \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x0D,                     \
	  "C_OSD_OP_CREATE")                                                    \
	V(C_OSD_OP_ROLLBACK,                                                    \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x0E,                     \
	  "C_OSD_OP_ROLLBACK")                                                  \
	V(C_OSD_OP_WATCH,                                                       \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x0F,                     \
	  "C_OSD_OP_WATCH")                                                     \
	V(C_OSD_OP_OMAPSETVALS,                                                 \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x15,                     \
	  "C_OSD_OP_OMAPSETVALS")                                               \
	V(C_OSD_OP_OMAPSETHEADER,                                               \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x16,                     \
	  "C_OSD_OP_OMAPSETHEADER")                                             \
	V(C_OSD_OP_OMAPCLEAR,                                                   \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x17,                     \
	  "C_OSD_OP_OMAPCLEAR")                                                 \
	V(C_OSD_OP_OMAPRMKEYS,                                                  \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x18,                     \
	  "C_OSD_OP_OMAPRMKEYS")                                                \
	V(C_OSD_OP_COPY_FROM,                                                   \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x1A,                     \
	  "C_OSD_OP_COPY_FROM")                                                 \
	V(C_OSD_OP_UNDIRTY,                                                     \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x1C,                     \
	  "C_OSD_OP_UNDIRTY")                                                   \
	V(C_OSD_OP_SETALLOCHINT,                                                \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_DATA  | 0x23,                     \
	  "C_OSD_OP_SETALLOCHINT")                                              \
	V(C_OSD_OP_SETXATTR,                                                    \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_ATTR  | 0x01,                     \
	  "C_OSD_OP_SETXATTR")                                                  \
	V(C_OSD_OP_SETXATTRS,                                                   \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_ATTR  | 0x02,                     \
	  "C_OSD_OP_SETXATTRS")                                                 \
	V(C_OSD_OP_RESETXATTRS,                                                 \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_ATTR  | 0x03,                     \
	  "C_OSD_OP_RESETXATTRS")                                               \
	V(C_OSD_OP_RMXATTR,                                                     \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_ATTR  | 0x04,                     \
	  "C_OSD_OP_RMXATTR")                                                   \
	V(C_OSD_OP_CLONERANGE,                                                  \
	  C_OSD_OP_MODE_WR    | C_OSD_OP_TYPE_MULTI | 0x01,                     \
	  "C_OSD_OP_CLONERANGE")                                                \
	V(C_OSD_OP_TMAPUP,                                                      \
	  C_OSD_OP_MODE_RMW   | C_OSD_OP_TYPE_DATA  | 0x0A,                     \
	  "C_OSD_OP_TMAPUP")                                                    \
	V(C_OSD_OP_TMAP2OMAP,                                                   \
	  C_OSD_OP_MODE_RMW   | C_OSD_OP_TYPE_DATA  | 0x22,                     \
	  "C_OSD_OP_TMAP2OMAP")                                                 \
	V(C_OSD_OP_PULL,                                                        \
	  C_OSD_OP_MODE_SUB                         | 0x01,                     \
	  "C_OSD_OP_PULL")                                                      \
	V(C_OSD_OP_PUSH,                                                        \
	  C_OSD_OP_MODE_SUB                         | 0x02,                     \
	  "C_OSD_OP_PUSH")                                                      \
	V(C_OSD_OP_BALANCEREADS,                                                \
	  C_OSD_OP_MODE_SUB                         | 0x03,                     \
	  "C_OSD_OP_BALANCEREADS")                                              \
	V(C_OSD_OP_UNBALANCEREADS,                                              \
	  C_OSD_OP_MODE_SUB                         | 0x04,                     \
	  "C_OSD_OP_UNBALANCEREADS")                                            \
	V(C_OSD_OP_SCRUB,                                                       \
	  C_OSD_OP_MODE_SUB                         | 0x05,                     \
	  "C_OSD_OP_SCRUB")                                                     \
	V(C_OSD_OP_SCRUB_RESERVE,                                               \
	  C_OSD_OP_MODE_SUB                         | 0x06,                     \
	  "C_OSD_OP_SCRUB_RESERVE")                                             \
	V(C_OSD_OP_SCRUB_UNRESERVE,                                             \
	  C_OSD_OP_MODE_SUB                         | 0x07,                     \
	  "C_OSD_OP_SCRUB_UNRESERVE")                                           \
	V(C_OSD_OP_SCRUB_STOP,                                                  \
	  C_OSD_OP_MODE_SUB                         | 0x08,                     \
	  "C_OSD_OP_SCRUB_STOP")                                                \
	V(C_OSD_OP_SCRUB_MAP,                                                   \
	  C_OSD_OP_MODE_SUB                         | 0x09,                     \
	  "C_OSD_OP_SCRUB_MAP")                                                 \
	V(C_OSD_OP_CACHE_FLUSH,                                                 \
	  C_OSD_OP_MODE_CACHE | C_OSD_OP_TYPE_DATA  | 0x1F,                     \
	  "C_OSD_OP_CACHE_FLUSH")                                               \
	V(C_OSD_OP_CACHE_EVICT,                                                 \
	  C_OSD_OP_MODE_CACHE | C_OSD_OP_TYPE_DATA  | 0x20,                     \
	  "C_OSD_OP_CACHE_EVICT")                                               \
	V(C_OSD_OP_CACHE_TRY_FLUSH,                                             \
	  C_OSD_OP_MODE_CACHE | C_OSD_OP_TYPE_DATA  | 0x21,                     \
	  "C_OSD_OP_CACHE_TRY_FLUSH")

typedef VALUE_STRING_ENUM(c_osd_optype_strings) c_osd_optype;
VALUE_STRING_ARRAY(c_osd_optype_strings);

static const
value_string_ext c_osd_op_strings_ext = VALUE_STRING_EXT_INIT(c_osd_optype_strings);

static
const char *c_osd_op_string(c_osd_optype val)
{
	return val_to_str_ext(val, &c_osd_op_strings_ext, "Unknown (0x%04x)");
}

/** Node type database. */
#define c_node_type_strings_LIST(V) \
	V(C_NODE_TYPE_UNKNOWN, 0x00, "Unknown",               "unknown") \
	V(C_NODE_TYPE_MON,     0x01, "Monitor",               "mon"    ) \
	V(C_NODE_TYPE_MDS,     0x02, "Meta Data Server",      "mds"    ) \
	V(C_NODE_TYPE_OSD,     0x04, "Object Storage Daemon", "osd"    ) \
	V(C_NODE_TYPE_CLIENT,  0x08, "Client",                "client" ) \
	V(C_NODE_TYPE_AUTH,    0x20, "Authentication Server", "auth"   ) \

#define C_EXTRACT_123(a, b, c, ...)    (a,b,c)
#define C_EXTRACT_124(a, b, c, d, ...) (a,b,d)
#define C_EVAL1(...) __VA_ARGS__

/** Extract the full names to create a value_string list. */
#define c_node_type_strings_VALUE_STRING_LIST(V) \
	C_EVAL1(c_node_type_strings_LIST(V C_EXTRACT_123))

/** Extract the abbreviations to create a value_string list. */
#define c_node_type_abbr_strings_VALUE_STRING_LIST(V) \
	C_EVAL1(c_node_type_strings_LIST(V C_EXTRACT_124))

typedef VALUE_STRING_ENUM(c_node_type_strings) c_node_type;
VALUE_STRING_ARRAY(c_node_type_strings);

static
const char *c_node_type_string(c_node_type val)
{
	return val_to_str(val, c_node_type_strings, "Unknown (0x%02x)");
}

VALUE_STRING_ARRAY(c_node_type_abbr_strings);

static
const char *c_node_type_abbr_string(c_node_type val)
{
	return val_to_str(val, c_node_type_abbr_strings, "Unknown (0x%02x)");
}

enum c_mon_sub_flags {
	C_MON_SUB_FLAG_ONETIME = 0x01
};

typedef enum _c_state {
	C_STATE_NEW,
	C_STATE_OPEN
} c_state;

typedef struct _c_node_name {
	const char *slug;
	const char *type_str;
	guint64 id;
	c_node_type type;
} c_node_name;

static
void c_node_name_init(c_node_name *d)
{
	d->slug     = NULL;
	d->type_str = NULL;
	d->id       = G_MAXUINT64;
	d->type     = C_NODE_TYPE_UNKNOWN;
}

typedef struct _c_node {
	address addr;
	c_node_name name;
	c_state state;
	guint16 port;
} c_node;

static
void c_node_init(c_node *n)
{
	/* @HELP: n->addr is there a sane way to initialize this? */
	c_node_name_init(&n->name);
	n->port = 0xFFFF;
	n->state = C_STATE_NEW;
}

static
c_node *c_node_copy(c_node *src, c_node *dst)
{
	dst->name = src->name;
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
	return c_conv_data_copy(d, wmem_new(wmem_file_scope(), c_conv_data));
}

static
c_conv_data* c_conv_data_new(void)
{
	c_conv_data *r;
	r = wmem_new(wmem_file_scope(), c_conv_data);
	c_conv_data_init(r);
	return r;
}

typedef struct _c_header {
	guint64 seq;
	guint64 tid;
	c_msg_type type;
	guint16 ver;
	guint8  priority;
	c_node_name src;
} c_header;

static
void c_header_init(c_header *h)
{
	h->seq      = 0;
	h->tid      = 0;
	h->type     = C_MSG_UNKNOWN;
	h->priority = 0;
	h->ver      = 0;
	memset(&h->src, 0, sizeof(h->src));
}

typedef struct _c_pkt_data {
	conversation_t *conv; /* The wireshark conversation. */
	c_conv_data *convd;   /* The Ceph conversation data. */
	c_node *src;          /* The node in convd that sent this message. */
	c_node *dst;          /* The node in convd that is receiving this message. */
	
	proto_item  *item_root;   /* The root proto_item for the message. */
	proto_item  *tree_filter; /* The filter data tree. */
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
c_pkt_data_init(c_pkt_data *d, packet_info *pinfo, guint off)
{
	/* Get conversation to store/retrieve connection data. */
	d->conv = find_or_create_conversation(pinfo);
	g_assert(d->conv && "find_or_create_conversation() returned NULL");
	
	if (pinfo->fd->flags.visited)
	{
		/* Retrieve the saved state. */
		d->convd = (c_conv_data*)p_get_proto_data(wmem_file_scope(), pinfo, proto_ceph, off);
		DISSECTOR_ASSERT_HINT(d->convd, "Frame visited, but no saved state.");
		/* Make a copy and use that so we don't mess up the original. */
		d->convd = c_conv_data_copy(d->convd, wmem_new(wmem_packet_scope(), c_conv_data));
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
		p_add_proto_data(wmem_file_scope(), pinfo, proto_ceph, off,
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
	
	ti = proto_tree_add_item(root, hf_sockaddr, tvb, off, C_SIZE_SOCKADDR_STORAGE, ENC_NA);
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
	                       c_node_type_string((c_node_type)type),
	                       addr.str);
	
	return off;
}

enum c_size_entity_name {
	C_SIZE_ENTITY_NAME = 9
};

static
guint c_dissect_node_name(proto_tree *root, c_node_name *out,
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
	c_node_name d;
	
	ti = proto_tree_add_item(root, hf_node_name,
	                         tvb, off, C_SIZE_ENTITY_NAME, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_node_name);
	
	d.type     = (c_node_type)tvb_get_guint8(tvb, off);
	d.type_str = c_node_type_abbr_string(d.type);
	proto_tree_add_item(tree, hf_node_type,
	                    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;
	
	d.id   = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_node_id,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	if (d.id == G_MAXUINT64)
	{
		d.slug = d.type_str;
	}
	else
	{
		d.slug = wmem_strdup_printf(wmem_packet_scope(), "%s%"G_GINT64_MODIFIER"u",
		                            d.type_str,
		                            d.id);
	}
	
	proto_item_append_text(ti, ": %s", d.slug);
	
	if (out) *out = d;
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

enum c_osd_flags {
	C_OSD_FLAG_ACK            = 0x00000001,  /* want (or is) "ack" ack */
	C_OSD_FLAG_ONNVRAM        = 0x00000002,  /* want (or is) "onnvram" ack */
	C_OSD_FLAG_ONDISK         = 0x00000004,  /* want (or is) "ondisk" ack */
	C_OSD_FLAG_RETRY          = 0x00000008,  /* resend attempt */
	C_OSD_FLAG_READ           = 0x00000010,  /* op may read */
	C_OSD_FLAG_WRITE          = 0x00000020,  /* op may write */
	C_OSD_FLAG_ORDERSNAP      = 0x00000040,  /* EOLDSNAP if snapc is out of order */
	C_OSD_FLAG_PEERSTAT_OLD   = 0x00000080,  /* DEPRECATED msg includes osd_peer_stat */
	C_OSD_FLAG_BALANCE_READS  = 0x00000100,
	C_OSD_FLAG_PARALLELEXEC   = 0x00000200,  /* execute op in parallel */
	C_OSD_FLAG_PGOP           = 0x00000400,  /* pg op, no object */
	C_OSD_FLAG_EXEC           = 0x00000800,  /* op may exec */
	C_OSD_FLAG_EXEC_PUBLIC    = 0x00001000,  /* DEPRECATED op may exec (public) */
	C_OSD_FLAG_LOCALIZE_READS = 0x00002000,  /* read from nearby replica, if any */
	C_OSD_FLAG_RWORDERED      = 0x00004000,  /* order wrt concurrent reads */
	C_OSD_FLAG_IGNORE_CACHE   = 0x00008000,  /* ignore cache logic */
	C_OSD_FLAG_SKIPRWLOCKS    = 0x00010000,  /* skip rw locks */
	C_OSD_FLAG_IGNORE_OVERLAY = 0x00020000,  /* ignore pool overlay */
	C_OSD_FLAG_FLUSH          = 0x00040000,  /* this is part of flush */
	C_OSD_FLAG_MAP_SNAP_CLONE = 0x00080000,  /* map snap direct to clone id */
	C_OSD_FLAG_ENFORCE_SNAPC  = 0x00100000   /* use snapc provided even if pool uses pool snaps */
};

static
guint c_dissect_osd_flags(proto_tree *tree,
                          tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	static const int *flags[] = {
		&hf_osd_flag_ack,
		&hf_osd_flag_onnvram,
		&hf_osd_flag_ondisk,
		&hf_osd_flag_retry,
		&hf_osd_flag_read,
		&hf_osd_flag_write,
		&hf_osd_flag_ordersnap,
		&hf_osd_flag_peerstat_old,
		&hf_osd_flag_balance_reads,
		&hf_osd_flag_parallelexec,
		&hf_osd_flag_pgop,
		&hf_osd_flag_exec,
		&hf_osd_flag_exec_public,
		&hf_osd_flag_localize_reads,
		&hf_osd_flag_rwordered,
		&hf_osd_flag_ignore_cache,
		&hf_osd_flag_skiprwlocks,
		&hf_osd_flag_ignore_overlay,
		&hf_osd_flag_flush,
		&hf_osd_flag_map_snap_clone,
		&hf_osd_flag_enforce_snapc,
		NULL
	};
	
	proto_tree_add_bitmask(tree, tvb, off, hf_osd_flags, hf_osd_flags,
	                       flags, ENC_LITTLE_ENDIAN);
	
	return off+4;
}

/** Dissect a length-delimited binary blob.
 */
static
guint c_dissect_blob(proto_tree *root, int hf, int hf_data, int hf_len,
                     tvbuff_t *tvb, guint off)
{
	proto_item *ti;
	proto_tree *tree;
	guint32 size;
	const char *hex;
	
	size = tvb_get_letohl(tvb, off);
	hex  = bytestring_to_str(wmem_packet_scope(),
	                         tvb_get_ptr(tvb, off+4, size), size,
	                         '\0');
	
	ti = proto_tree_add_item(root, hf, tvb, off, size+4, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_data);
	
	proto_item_append_text(ti, ", Size: %"G_GINT32_MODIFIER"u", size);
	if (size) proto_item_append_text(ti, ", Data: %s", hex);
	
	proto_tree_add_item(tree, hf_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_data,
	                    tvb, off, size, ENC_NA);
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
	d.str  = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, off+4, d.size, ENC_ASCII);
	
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

typedef struct _c_encoded {
	guint8  version;
	guint8  compat;
	guint32 size;
} c_encoded;

/** Dissect and 'encoded' struct.
 * 
 * @return The offset of the data.
 */
static
guint c_dissect_encoded(proto_tree *tree, c_encoded *enc,
                        tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	enc->version = tvb_get_guint8(tvb, off);
	proto_tree_add_item(tree, hf_encoded_ver,    tvb, off++, 1, ENC_LITTLE_ENDIAN);
	enc->compat = tvb_get_guint8(tvb, off);
	proto_tree_add_item(tree, hf_encoded_compat, tvb, off++, 1, ENC_LITTLE_ENDIAN);
	
	enc->size = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_encoded_size, tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
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
	
	//@TODO: Use FT_ABSOLUTE_TIME
	
	ti   = proto_tree_add_item(root, hf_time, tvb, off, C_SIZE_TIMESPEC, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_time);
	
	proto_tree_add_item(tree, hf_time_sec,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_time_nsec,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	return off;
}

enum c_size_eversion {
	C_SIZE_EVERSION = 12
};

static
guint c_dissect_eversion(proto_tree *root, gint hf,
                         tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	guint64 ver;
	guint32 epoch;
	
	ti   = proto_tree_add_item(root, hf, tvb, off, C_SIZE_EVERSION, ENC_NA);
	tree = proto_item_add_subtree(ti, hf);
	
	/*** version_t ***/
	ver = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_version, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	/*** epoch_t ***/
	epoch = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_epoch, tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	proto_item_append_text(ti,
	                       ", Version: %"G_GINT64_MODIFIER"d"
	                       ", Epoch: %"G_GINT32_MODIFIER"d",
	                       ver, epoch);
	
	return off;
}

static
guint c_dissect_object_locator(proto_tree *root, gint hf,
                               tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enchdr;
	guint expectedoff;
	c_str str;
	gint64 hash;
	
	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, hf);
	
	off = c_dissect_encoded(tree, &enchdr, tvb, off, data);
	expectedoff = off + enchdr.size;
	
	proto_item_append_text(ti, ", Pool: %"G_GINT64_MODIFIER"d",
	                       (gint64)tvb_get_letoh64(tvb, off));
	proto_tree_add_item(tree, hf_pool, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	off += 4; /* Skip over preferred == -1 that old code used. */
	
	if (tvb_get_letohl(tvb, off))
	{
		off = c_dissect_str(tree, hf_key, &str, tvb, off);
		proto_item_append_text(ti, ", Key: '%s'", str.str);
	}
	else off += 4; /* If string is empty we should use hash. */
	
	off = c_dissect_str(tree, hf_namespace, &str, tvb, off);
	if (str.size)
		proto_item_append_text(ti, ", Namespace: '%s'", str.str);
	
	hash = tvb_get_letoh64(tvb, off);
	if (hash >= 0)
	{
		proto_tree_add_item(tree, hf_hash, tvb, off, 8, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, ", Hash: %"G_GINT64_MODIFIER"d", hash);
	}
	off += 8;
	
	//@TODO: Warn if not key or hash.
	//@TODO: Warn if off != expectedoff
	
	return off;
}

static
guint c_dissect_pgid(proto_tree *root, gint hf,
                     tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	gint32 preferred;
	
	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, hf);
	
	//@TODO: version check.
	
	proto_tree_add_item(tree, hf_pgid_ver, tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;
	
	proto_item_append_text(ti, ", Pool: %"G_GINT64_MODIFIER"d",
	                       tvb_get_letoh64(tvb, off));
	proto_tree_add_item(tree, hf_pgid_pool, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	proto_item_append_text(ti, ", Seed: %08"G_GINT32_MODIFIER"X",
	                       tvb_get_letohl(tvb, off));
	proto_tree_add_item(tree, hf_pgid_seed, tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	preferred = tvb_get_letohl(tvb, off);
	if (preferred >= 0)
		proto_item_append_text(ti, ", Prefer: %"G_GINT32_MODIFIER"d", preferred);
	proto_tree_add_item(tree, hf_pgid_preferred, tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	return off;
}

typedef struct _c_osd_op {
	c_osd_optype type;
	const char *type_str;
	guint32 payload_len;
} c_osd_op;

static
guint c_dissect_osd_op(proto_tree *root, gint hf, c_osd_op *out,
                       tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	c_osd_op d;
	
	/* From ceph:/src/include/rados.h
	struct ceph_osd_op {
		__le16 op;           // CEPH_OSD_OP_*
		__le32 flags;        // CEPH_OSD_FLAG_*
		union {
			struct {
				__le64 offset, length;
				__le64 truncate_size;
				__le32 truncate_seq;
			} __attribute__ ((packed)) extent;
			struct {
				__le32 name_len;
				__le32 value_len;
				__u8 cmp_op;       // CEPH_OSD_CMPXATTR_OP_*
				__u8 cmp_mode;     // CEPH_OSD_CMPXATTR_MODE_*
			} __attribute__ ((packed)) xattr;
			struct {
				__u8 class_len;
				__u8 method_len;
				__u8 argc;
				__le32 indata_len;
			} __attribute__ ((packed)) cls;
			struct {
				__le64 count;
				__le32 start_epoch; // for the pgls sequence
			} __attribute__ ((packed)) pgls;
			struct {
				__le64 snapid;
			} __attribute__ ((packed)) snap;
			struct {
				__le64 cookie;
				__le64 ver;
				__u8 flag; // 0 = unwatch, 1 = watch
			} __attribute__ ((packed)) watch;
			struct {
				__le64 unused;
				__le64 ver;
			} __attribute__ ((packed)) assert_ver;
			struct {
				__le64 offset, length;
				__le64 src_offset;
			} __attribute__ ((packed)) clonerange;
			struct {
				__le64 max;     // max data in reply
			} __attribute__ ((packed)) copy_get;
			struct {
				__le64 snapid;
				__le64 src_version;
				__u8 flags;
			} __attribute__ ((packed)) copy_from;
			struct {
				struct ceph_timespec stamp;
			} __attribute__ ((packed)) hit_set_get;
			struct {
				__u8 flags;
			} __attribute__ ((packed)) tmap2omap;
			struct {
				__le64 expected_object_size;
				__le64 expected_write_size;
			} __attribute__ ((packed)) alloc_hint;
		};
		__le32 payload_len;
	} __attribute__ ((packed));
	*/
	
	d.type = (c_osd_optype)tvb_get_letohs(tvb, off);
	
	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, hf);
	
	d.type_str = c_osd_op_string(d.type);
	proto_item_append_text(ti, ", Type: %s", d.type_str);
	proto_tree_add_item(tree, hf_osd_op_type, tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	
	off = c_dissect_osd_flags(tree, tvb, off, data);
	
	/***
		Stop moving off here.  The size of the individual message doesn't
		matter, only the size of the largest, which is added below.
	***/
	
	switch (d.type)
	{
	default:
		proto_tree_add_item(tree, hf_osd_op_data, tvb, off, 28, ENC_NA);
		//@TODO: Warn.
	}
	
	off += 28;
	
	d.payload_len = tvb_get_letohl(tvb, off);
	proto_item_append_text(ti, ", Data Length: %"G_GINT32_MODIFIER"d",
	                       d.payload_len);
	proto_tree_add_item(tree, hf_osd_op_payload_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	if (out) *out = d;
	return off;
}

static
guint c_dissect_redirect(proto_tree *root, gint hf,
                         tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	guint offexpected;
	c_encoded enc;
	
	ti = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, hf);
	
	off = c_dissect_encoded(tree, &enc, tvb, off, data);
	offexpected = off + enc.size;
	
	off = c_dissect_object_locator(tree, hf_osd_redirect_oloc, tvb, off, data);
	
	if (tvb_get_letohl(tvb, off))
	{
		off = c_dissect_str(tree, hf_osd_redirect_obj, NULL, tvb, off);
	}
	else off += 4;
	
	off = c_dissect_blob(tree, hf_osd_redirect_osdinstr,
	                     hf_osd_redirect_osdinstr_data, hf_osd_redirect_osdinstr_len,
	                     tvb, off);
	
	//@TODO: check off == expectedoff
	proto_item_set_end(ti, tvb, off);
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
	
	ti = proto_tree_add_item(root, hf_paxos, tvb, off, C_SIZE_PAXOS, ENC_NA);
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
	
	ti = proto_tree_add_item(root, hf_msg_mon_map, tvb, 0, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_mon_map);
	
	return c_dissect_blob(tree, hf_msg_mon_map_data,
	                      hf_msg_mon_map_data_data, hf_msg_mon_map_data_len,
	                      tvb, 0);
	
	//@TODO: Parse Mon Map.
}

static
guint c_dissect_msg_mon_sub(proto_tree *root,
                           tvbuff_t *tvb,
                           guint front_len, guint middle_len _U_, guint data_len _U_,
                           c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint len;
	gboolean first = 1;
	c_str str;
	
	/* ceph:/src/messages/MMonSubscribe.h */
	
	c_set_type(data, "Mon Subscribe");
	proto_item_append_text(data->item_root, ", To:");
	
	ti = proto_tree_add_item(root, hf_msg_mon_sub, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_mon_sub);
	
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
		
		ti = proto_tree_add_item(tree, hf_msg_mon_sub_item, tvb, off, -1, ENC_NA);
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
	
	ti = proto_tree_add_item(root, hf_msg_mon_sub_ack, tvb, off, front_len, ENC_NA);
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
	
	ti = proto_tree_add_item(root, hf_msg_auth, tvb, off, front_len-off, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_auth);
	
	proto_item_append_text(data->item_root, ", Proto: 0x%02x",
	                       tvb_get_letohl(tvb, off));
	proto_tree_add_item(tree, hf_msg_auth_proto,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	off = c_dissect_blob(tree, hf_msg_auth_payload,
	                     hf_msg_auth_payload_data, hf_msg_auth_payload_len,
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
	
	ti = proto_tree_add_item(root, hf_msg_auth_reply, tvb, off, front_len, ENC_NA);
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
	
	off = c_dissect_blob(tree, hf_msg_auth_reply_data,
	                     hf_msg_auth_reply_data_data, hf_msg_auth_reply_data_len,
	                     tvb, off);
	off = c_dissect_str(tree, hf_msg_auth_reply_msg, NULL, tvb, off);
	
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
	
	ti = proto_tree_add_item(root, hf_msg_osd_map, tvb, off, front_len, ENC_NA);
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
		ti = proto_tree_add_item(tree, hf_msg_osd_map_inc, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, hf_msg_osd_map_inc);
		
		proto_tree_add_item(subtree, hf_msg_osd_map_epoch,
		                    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
		off = c_dissect_blob(subtree, hf_msg_osd_map_data,
		                     hf_msg_osd_map_data_data, hf_msg_osd_map_data_len,
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
		ti = proto_tree_add_item(tree, hf_msg_osd_map_map, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, hf_msg_osd_map_map);
		
		proto_tree_add_item(subtree, hf_msg_osd_map_epoch,
		                    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
		off = c_dissect_blob(subtree, hf_msg_osd_map_data,
		                     hf_msg_osd_map_data_data, hf_msg_osd_map_data_len,
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

/** OSD Operation (0x002A)
 */
static
guint c_dissect_msg_osd_op(proto_tree *root,
                           tvbuff_t *tvb,
                           guint front_len, guint middle_len _U_, guint data_len _U_,
                           c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint16 opslen, i;
	c_osd_op *ops;
	c_str str;
	
	c_set_type(data, "OSD Operation");
	
	ti = proto_tree_add_item(root, hf_msg_osd_op, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_osd_op);
	
	proto_tree_add_item(tree, hf_msg_osd_op_client_inc,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	proto_tree_add_item(tree, hf_msg_osd_op_osdmap_epoch,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	off = c_dissect_osd_flags(tree, tvb, off, data);
	
	proto_tree_add_item(tree, hf_msg_osd_op_mtime,
	                    tvb, off, 8, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
	off += 8;
	
	off = c_dissect_eversion(tree, hf_msg_osd_op_reassert_version, tvb, off, data);
	
	off = c_dissect_object_locator(tree, hf_msg_osd_op_oloc, tvb, off, data);
	
	off = c_dissect_pgid(tree, hf_msg_osd_op_pgid, tvb, off, data);
	
	off = c_dissect_str(tree, hf_msg_osd_op_oid, &str, tvb, off);
	
	opslen = tvb_get_letohs(tvb, off);
	proto_item_append_text(ti, ", Operations: %"G_GINT32_MODIFIER"d", opslen);
	proto_tree_add_item(tree, hf_msg_osd_op_ops_len, tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	ops = wmem_alloc_array(wmem_packet_scope(), c_osd_op, opslen);
	for (i = 0; i < opslen; i++)
	{
		off = c_dissect_osd_op(tree, hf_msg_osd_op_op, &ops[i], tvb, off, data);
	}
	
	proto_tree_add_item(tree, hf_msg_osd_op_snap_id, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_msg_osd_op_snap_seq, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_osd_op_snaps_len, tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(tree, hf_msg_osd_op_snap, tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}
	
	if (data->header.ver >= 4)
	{
		proto_tree_add_item(tree, hf_msg_osd_op_retry_attempt, tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}
	
	//@TODO: Check off == font_len;
	
	for (i = 0; i < opslen; i++)
	{
		proto_tree_add_item(tree, hf_msg_osd_op_payload,
		                    tvb, off, ops[i].payload_len, ENC_NA);
		off += ops[i].payload_len;
	}
	
	return off;
}

/** OSD Operation Reply (0x002B)
 */
static
guint c_dissect_msg_osd_opreply(proto_tree *root,
                                tvbuff_t *tvb,
                                guint front_len, guint middle_len _U_, guint data_len _U_,
                                c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	c_str str;
	guint32 i;
	guint32 opslen;
	c_osd_op *ops;
	
	c_set_type(data, "OSD Operation Reply");
	
	ti = proto_tree_add_item(root, hf_msg_osd_opreply, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_osd_opreply);
	
	off = c_dissect_str(tree, hf_msg_osd_opreply_oid, &str, tvb, off);
	
	off = c_dissect_pgid(tree, hf_msg_osd_opreply_pgid, tvb, off, data);
	
	off = c_dissect_osd_flags(tree, tvb, off, data);
	off += 4; /* flags is 64 bit but it appears that the higher 32 are ignored. */
	
	proto_tree_add_item(tree, hf_msg_osd_opreply_result,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	off = c_dissect_eversion(tree, hf_msg_osd_opreply_bad_replay_ver,
	                         tvb, off, data);
	
	proto_tree_add_item(tree, hf_msg_osd_opreply_osdmap_epoch,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	opslen = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_osd_opreply_ops_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	ops = wmem_alloc_array(wmem_file_scope(), c_osd_op, opslen);
	off += 4;
	for (i = 0; i < opslen; i++)
	{
		off = c_dissect_osd_op(tree, hf_msg_osd_opreply_op, &ops[i],
		                       tvb, off, data);
	}
	
	if (data->header.ver >= 3)
	{
		proto_tree_add_item(tree, hf_msg_osd_opreply_retry_attempt,
		                    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}
	
	if (data->header.ver >= 4)
	{
		for (i = 0; i < opslen; i++)
		{
			proto_tree_add_item(tree, hf_msg_osd_opreply_rval,
			                    tvb, off, 4, ENC_LITTLE_ENDIAN);
			off += 4;
		}
	}
	
	if (data->header.ver >= 5)
	{
		off = c_dissect_eversion(tree, hf_msg_osd_opreply_replay_ver,
		                         tvb, off, data);
		proto_tree_add_item(tree, hf_msg_osd_opreply_user_ver,
		                    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}
	
	if (data->header.ver >= 6)
	{
		off = c_dissect_redirect(tree, hf_msg_osd_opreply_redirect,
		                         tvb, off, data);
	}
	
	//@TODO: Check off == font_len;
	
	if (data->header.ver >= 4)
	{
		for (i = 0; i < opslen; i++)
		{
			proto_tree_add_item(tree, hf_msg_osd_opreply_payload,
			                    tvb, off, ops[i].payload_len, ENC_NA);
			off += ops[i].payload_len;
		}
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
	
	ti = proto_tree_add_item(root, hf_msg_mon_cmd, tvb, off, front_len, ENC_NA);
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
		ti = proto_tree_add_item(tree, hf_msg_mon_cmd_arg, tvb, off, -1, ENC_NA);
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
	
	ti = proto_tree_add_item(root, hf_msg_mon_cmd_ack, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, hf_msg_mon_cmd_ack);
	
	proto_tree_add_item(tree, hf_msg_mon_cmd_ack_code,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	off = c_dissect_str(tree, hf_msg_mon_cmd_ack_res, NULL, tvb, off);
	
	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_cmd_ack_arg_len,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	while (i--)
	{
		ti = proto_tree_add_item(tree, hf_msg_mon_cmd_ack_arg, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, hf_msg_mon_cmd_ack_arg);
		
		off = c_dissect_str(subtree, hf_msg_mon_cmd_ack_arg_str, NULL,
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
	c_msg_type type;
	guint32 front_len, middle_len, data_len;
	guint size, parsedsize;
	
	if (!tvb_bytes_exist(tvb, off, C_OFF_HEAD1 + C_SIZE_HEAD1))
		return C_NEEDMORE;
	
	front_len  = tvb_get_letohl(tvb, off + C_OFF_HEAD1 + 0);
	middle_len = tvb_get_letohl(tvb, off + C_OFF_HEAD1 + 4);
	data_len   = tvb_get_letohl(tvb, off + C_OFF_HEAD1 + 8);
	
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
	
	ti = proto_tree_add_item(tree, hf_head, tvb, off, C_SIZE_HEAD, ENC_NA);
	subtree = proto_item_add_subtree(ti, hf_head);
	
	data->header.seq = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(subtree, hf_head_seq,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	data->header.tid = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(subtree, hf_head_tid,
	                    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	
	data->header.type = type = (c_msg_type)tvb_get_letohs(tvb, off);
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
	
	off = c_dissect_node_name(subtree, &data->header.src, tvb, off, data);
	
	/*** Copy the data to the state structure. ***/
	if (!data->src->name.slug)
	{
		data->src->name.slug     = wmem_strdup(wmem_file_scope(), data->header.src.slug);
		data->src->name.type_str = wmem_strdup(wmem_file_scope(), data->header.src.type_str);
		data->src->name.type     = data->header.src.type;
		data->src->name.id       = data->header.src.id;
	}
	
	proto_tree_add_item(subtree, hf_head_compat_version,
	                    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	proto_tree_add_item(subtree, hf_head_reserved,
	                    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	proto_tree_add_item(subtree, hf_head_crc,
	                    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	
	proto_item_append_text(ti, ", Type: %s, From: %s",
	                       c_msg_type_string(type),
	                       data->header.src.slug);
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
	C_HANDLE_MSG(C_CEPH_MSG_OSD_OP,            c_dissect_msg_osd_op)
	C_HANDLE_MSG(C_CEPH_MSG_OSD_OPREPLY,       c_dissect_msg_osd_opreply)
	C_HANDLE_MSG(C_MSG_MON_COMMAND,            c_dissect_msg_mon_cmd)
	C_HANDLE_MSG(C_MSG_MON_COMMAND_ACK,        c_dissect_msg_mon_cmd_ack)
	
	default:
		parsedsize = C_CALL_MSG(c_dissect_msg_unknown);
#undef C_CALL_MSG
#undef C_HANDLE_MSG
	}
	
	size = front_len + middle_len + data_len;
	
	/* Did the message dissector use all the data? */
	if (parsedsize < size)
	{
		ti = proto_tree_add_text(tree, tvb, off+parsedsize, size-parsedsize,
		                         "%"G_GINT32_MODIFIER"u unused byte%s",
		                         size-parsedsize,
		                         size-parsedsize == 1? "":"s");
		expert_add_info(data->pinfo, ti, &ei_unused);
	}
	
	off += size;
	
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
	
	ti = proto_tree_add_item(tree, hf_foot, tvb, off, C_SIZE_FOOT, ENC_NA);
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
	C_SIZE_HELLO_C = C_SIZE_ENTITY_ADDR + C_SIZE_CONNECT,
	C_HELLO_OFF_AUTHLEN = C_SIZE_ENTITY_ADDR + 28
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
	guint32 authlen;
	
	authlen = tvb_get_letohl(tvb, off+28);
	
	ti = proto_tree_add_item(root, hf_connect, tvb, off, C_SIZE_CONNECT, ENC_NA);
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
	
	//@TODO: Parse auth.
	proto_tree_add_item(tree, hf_connect_auth,
	                    tvb, off, authlen, ENC_NA);
	off += authlen;
	
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
	guint32 authlen;
	
	authlen = tvb_get_letohl(tvb, off+20);
	
	if (!tvb_bytes_exist(tvb, off, C_SIZE_CONNECT_REPLY + authlen))
		return off+C_SIZE_CONNECT_REPLY+authlen; /* We need more data to dissect. */
	
	c_set_type(data, "Connect Reply");
	
	ti = proto_tree_add_item(root, hf_connect_reply,
	                         tvb, off, C_SIZE_CONNECT_REPLY, ENC_NA);
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
	
	//@TODO: Parse auth.
	proto_tree_add_item(tree, hf_connect_auth,
	                    tvb, off, authlen, ENC_NA);
	off += authlen;
	
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
	
	proto_tree_add_item(tree, hf_banner, tvb, off, banlen, ENC_NA);
	off += banlen;
	
	if (c_from_server(data)) size = C_SIZE_HELLO_S;
	else {
		if (!tvb_bytes_exist(tvb, off, C_HELLO_OFF_AUTHLEN))
			return 0; /* Need More */
		
		size = C_SIZE_HELLO_C + tvb_get_letohl(tvb, off+C_HELLO_OFF_AUTHLEN);
	}
	
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
			"Unknown Tag" items (where only the first one is really
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
	proto_item *ti, *tif;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, proto_ceph, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_ceph);
	
	data->item_root = ti;
	
	tif = proto_tree_add_item(tree, hf_filter_data, tvb, off, -1, ENC_NA);
	data->tree_filter = proto_item_add_subtree(tif, hf_filter_data);
	
	if (data->src->state == C_STATE_NEW)
		off = c_dissect_new(tree, tvb, off, data);
	else
		off = c_dissect_msgr(tree, tvb, off, data);
	
	if (data->tree_filter) {
		/*** General Filter Data ***/
		proto_tree_add_string(data->tree_filter, hf_src_slug, NULL,0,0, data->src->name.slug);
		proto_tree_add_uint  (data->tree_filter, hf_src_type, NULL,0,0, data->src->name.type);
		proto_tree_add_string(data->tree_filter, hf_dst_slug, NULL,0,0, data->dst->name.slug);
		proto_tree_add_uint  (data->tree_filter, hf_dst_type, NULL,0,0, data->dst->name.type);
		
		proto_item_set_end(ti,  tvb, off);
		proto_item_set_end(tif, tvb, off);
	}
	
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
		c_pkt_data_init(&data, pinfo, tvb_offset_from_real_beginning(tvb));
		
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
	expert_module_t* expert_ceph;
	
	static hf_register_info hf[] = {
		{ &hf_filter_data, {
			"Filter Data", "ceph.filter",
			FT_NONE, BASE_NONE, NULL, 0,
			"A bunch of properties for convenient filtering.", HFILL
		} },
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
		{ &hf_src_slug, {
			"Source Node Name", "ceph.src",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_src_type, {
			"Source Node Type", "ceph.src.type",
			FT_UINT8, BASE_HEX, VALS(c_node_type_abbr_strings), 0,
			NULL, HFILL
		} },
		{ &hf_dst_slug, {
			"Destination Node Name", "ceph.dst",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_dst_type, {
			"Destination Node Type", "ceph.dst.type",
			FT_UINT8, BASE_HEX, VALS(c_node_type_abbr_strings), 0,
			NULL, HFILL
		} },
		{ &hf_banner, {
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
		{ &hf_encoded_ver, {
			"Encoding Version", "ceph.enc.ver",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_encoded_compat, {
			"Minimum compatible version", "ceph.enc.compat",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_encoded_size, {
			"Size", "ceph.nanoseconds",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Size of encoded message.", HFILL
		} },
		{ &hf_version, {
			"Version", "ceph.version",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_epoch, {
			"Epoch", "ceph.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pool, {
			"Pool", "ceph.pool",
			FT_INT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_key, {
			"Object Key", "ceph.key",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_namespace, {
			"Namespace", "ceph.namespace",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_hash, {
			"Object Hash", "ceph.hash",
			FT_INT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgid_ver, {
			"Placement Group Version", "ceph.pg.ver",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgid_pool, {
			"Pool", "ceph.pg.pool",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgid_seed, {
			"Seed", "ceph.pg.seed",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgid_preferred, {
			"Preferred", "ceph.pg.preferred",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_connect, {
			"Connection Negotiation", "ceph.connect",
			FT_NONE, BASE_NONE, NULL, 0,
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
		{ &hf_connect_auth, {
			"Authentication", "ceph.connect.auth",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Authentication data.", HFILL
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
		{ &hf_osd_flags, {
			"OSD Flags", "ceph.osd_flags",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_flag_ack, {
			"ACK", "ceph.osd_flags.ack",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ACK,
			"want (or is) \"ack\" ack", HFILL
		} },
		{ &hf_osd_flag_onnvram, {
			"ACK on NVRAM", "ceph.osd_flags.onnvram",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ONNVRAM,
			"want (or is) \"onnvram\" ack", HFILL
		} },
		{ &hf_osd_flag_ondisk, {
			"ACK on DISK", "ceph.osd_flags.ondisk",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ONDISK,
			"want (or is) \"ondisk\" ack", HFILL
		} },
		{ &hf_osd_flag_retry, {
			"Retry", "ceph.osd_flags.retry",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_RETRY,
			"resend attempt", HFILL
		} },
		{ &hf_osd_flag_read, {
			"Read", "ceph.osd_flags.read",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_READ,
			"op may read", HFILL
		} },
		{ &hf_osd_flag_write, {
			"Write", "ceph.osd_flags.write",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_WRITE,
			"op may write", HFILL
		} },
		{ &hf_osd_flag_ordersnap, {
			"ORDERSNAP", "ceph.osd_flags.ordersnap",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ORDERSNAP,
			"EOLDSNAP if snapc is out of order", HFILL
		} },
		{ &hf_osd_flag_peerstat_old, {
			"PEERSTAT_OLD", "ceph.osd_flags.peerstat_old",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_PEERSTAT_OLD,
			"DEPRECATED msg includes osd_peer_stat", HFILL
		} },
		{ &hf_osd_flag_balance_reads, {
			"BALANCE_READS", "ceph.osd_flags.balance_reads",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_BALANCE_READS,
			NULL, HFILL
		} },
		{ &hf_osd_flag_parallelexec, {
			"PARALLELEXEC", "ceph.osd_flags.parallelexec",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_PARALLELEXEC,
			"execute op in parallel", HFILL
		} },
		{ &hf_osd_flag_pgop, {
			"PGOP", "ceph.osd_flags.pgop",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_PGOP,
			"pg op, no object", HFILL
		} },
		{ &hf_osd_flag_exec, {
			"EXEC", "ceph.osd_flags.exec",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_EXEC,
			"op may exec", HFILL
		} },
		{ &hf_osd_flag_exec_public, {
			"EXEC_PUBLIC", "ceph.osd_flags.exec_public",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_EXEC_PUBLIC,
			"DEPRECATED op may exec (public)", HFILL
		} },
		{ &hf_osd_flag_localize_reads, {
			"LOCALIZE_READS", "ceph.osd_flags.localize_reads",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_LOCALIZE_READS,
			"read from nearby replica, if any", HFILL
		} },
		{ &hf_osd_flag_rwordered, {
			"RWORDERED", "ceph.osd_flags.rwordered",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_RWORDERED,
			"order wrt concurrent reads", HFILL
		} },
		{ &hf_osd_flag_ignore_cache, {
			"IGNORE_CACHE", "ceph.osd_flags.ignore_cache",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_IGNORE_CACHE,
			"ignore cache logic", HFILL
		} },
		{ &hf_osd_flag_skiprwlocks, {
			"SKIPRWLOCKS", "ceph.osd_flags.skiprwlocks",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_SKIPRWLOCKS,
			"skip rw locks", HFILL
		} },
		{ &hf_osd_flag_ignore_overlay, {
			"IGNORE_OVERLAY", "ceph.osd_flags.ignore_overlay",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_IGNORE_OVERLAY,
			"ignore pool overlay", HFILL
		} },
		{ &hf_osd_flag_flush, {
			"FLUSH", "ceph.osd_flags.flush",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_FLUSH,
			"this is part of flush", HFILL
		} },
		{ &hf_osd_flag_map_snap_clone, {
			"MAP_SNAP_CLONE", "ceph.osd_flags.map_snap_clone",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_MAP_SNAP_CLONE,
			"map snap direct to clone id", HFILL
		} },
		{ &hf_osd_flag_enforce_snapc, {
			"ENFORCE_SNAPC", "ceph.osd_flags.enforce_snapc",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ENFORCE_SNAPC,
			"use snapc provided even if pool uses pool snaps", HFILL
		} },
		{ &hf_osd_op_type, {
			"Operation", "ceph.osd_op.op",
			FT_UINT16, BASE_HEX|BASE_EXT_STRING, VALS(&c_osd_op_strings_ext), 0,
			NULL, HFILL
		} },
		{ &hf_osd_op_data, {
			"Operation Specific Data", "ceph.osd_op.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_op_payload_len, {
			"Payload Length", "ceph.osd_op.payload_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_redirect_oloc, {
			"Object Locater", "ceph.osd_redirect.oloc",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_redirect_obj, {
			"Object Name", "ceph.osd_redirect.obj",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Redirect to this object.", HFILL
		} },
		{ &hf_osd_redirect_osdinstr, {
			"OSD Instructions", "ceph.osd_redirect.osd_instructions",
			FT_NONE, BASE_NONE, NULL, 0,
			"Instructions to pass to the new target.", HFILL
		} },
		{ &hf_osd_redirect_osdinstr_data, {
			"Data", "ceph.osd_redirect.osd_instructions",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_redirect_osdinstr_len, {
			"Length", "ceph.osd_redirect.osd_instructions_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
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
			"Payload", "ceph",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_map_data_data, {
			"Data", "ceph.msg.mon_map.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_map_data_len, {
			"Length", "ceph.msg.mon_map.data_len",
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
			"Payload", "ceph",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_payload_data, {
			"Data", "ceph.msg.auth.payload",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_payload_len, {
			"Length", "ceph.msg.auth.payload_len",
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
			"Data", "ceph",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_data_data, {
			"Data", "ceph.msg.auth_reply.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_data_len, {
			"Length", "ceph.msg.auth_reply.data_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_msg, {
			"Message", "ceph.msg.auth_reply.msg",
			FT_STRING, BASE_NONE, NULL, 0,
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
			"Map Data", "ceph",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_data_data, {
			"Data", "ceph.msg.osd_map.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_data_len, {
			"Length", "ceph.msg.osd_map.data_len",
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
		{ &hf_msg_mon_cmd, { "Mon Command", "ceph.msg.mon_cmd",
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
		{ &hf_msg_mon_cmd_ack_data, {
			"Data", "ceph.msg.mon_cmd_ack.data",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op, {
			"OSD Operation", "ceph.msg.osd_op",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_client_inc, {
			"Client Inc", "ceph.msg.osd_op.client_inc",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_osdmap_epoch, {
			"OSD Map Epoch", "ceph.msg.osd_op.osdmap_epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_flags, {
			"Flags", "ceph.msg.osd_op.flags",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_mtime, { //@HELP is it mod time?
			"Modification Time", "ceph.msg.osd_op",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, //@HELP: Absolute or relative?
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_reassert_version, {
			"Reassert Version", "ceph.msg.osd_op.reassert_version",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_oloc, {
			"Object Locater", "ceph.msg.osd_op.oloc",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_pgid, {
			"Placement Group ID", "ceph.msg.osd_op.pgid",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_oid, {
			"Object ID", "ceph.msg.osd_op.oid",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_ops_len, {
			"Operation Count", "ceph.msg.osd_op.ops_len",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_op, {
			"Operation", "ceph.msg.osd_op.op",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_snap_id, {
			"Snap ID", "ceph.msg.osd_op.snap_id",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_snap_seq, {
			"Snap Sequence", "ceph.msg.osd_op.snap_seq",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_snaps_len, {
			"Snap Count", "ceph.msg.osd_op.snaps_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_snap, {
			"Snap", "ceph.msg.osd_op.snaps",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_retry_attempt, {
			"Retry Attempt", "ceph.msg.osd_op.retry",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_payload, {
			"Operation Payload", "ceph.msg.osd_op.op_payload",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply, {
			"OSD Operation Reply", "ceph.msg.osd_opreply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_oid, {
			"Object ID", "ceph.msg.osd_opreply.oid",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_pgid, {
			"Placement Group ID", "ceph.msg.osd_opreply.pgid",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_flags, {
			"Flags", "ceph.msg.osd_opreply.flags",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_result, {
			"Result", "ceph.msg.osd_opreply.result",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_bad_replay_ver, {
			"Bad Replay Version", "ceph.msg.osd_opreply.bad_replay_ver",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_replay_ver, {
			"Replay Version", "ceph.msg.osd_opreply.replay_ver",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_user_ver, {
			"User Version", "ceph.msg.osd_opreply.user_ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_redirect, {
			"Redirect", "ceph.msg.osd_opreply.user_ver",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_osdmap_epoch, {
			"OSD Map Epoch", "ceph.msg.osd_opreply.osdmap_epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_ops_len, {
			"Operation Count", "ceph.msg.osd_opreply.ops_len",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_op, {
			"Operation", "ceph.msg.osd_opreply.op",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_retry_attempt, {
			"Retry Attempt", "ceph.msg.osd_opreply.retry",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_rval, {
			"Operation Return Value", "ceph.msg.osd_opreply.rval",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_payload, {
			"Operation Result", "ceph.msg.osd_opreply.payload",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
	};
	
	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ceph,
	};
	
	/* Expert info items. */
	static ei_register_info ei[] = {
		{ &ei_unused, {
			"ceph.unused", PI_UNDECODED, PI_WARN,
			"Unused data in message.  This usually indicates an error by the "
			"sender or a bug in the dissector.", EXPFILL
		} },
	};
	
	/* Register the protocol name and description */
	proto_ceph = proto_register_protocol("Ceph", "Ceph", "ceph");
	
	/* Required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_ceph, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_ceph = expert_register_protocol(proto_ceph);
	expert_register_field_array(expert_ceph, ei, array_length(ei));
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
