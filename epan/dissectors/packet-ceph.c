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

#include "packet-tcp.h"

/* Forward declaration that is needed below if using the
 * proto_reg_handoff_ceph function as a callback for when protocol
 * preferences get changed. */
void proto_reg_handoff_ceph(void);
void proto_register_ceph(void);

/* Initialize the protocol and registered fields */
static int proto_ceph                      = -1;
static int hf_type                         = -1;
static int hf_node_id                      = -1;
static int hf_node_type                    = -1;
static int hf_node_name                    = -1;
static int hf_version                      = -1;
static int hf_sockaddr_client              = -1;
static int hf_sockaddr_server              = -1;
static int hf_inet_family                  = -1;
static int hf_port                         = -1;
static int hf_addr_ipv4                    = -1;
static int hf_addr_ipv6                    = -1;
static int hf_features                     = -1;
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
static int hf_front                        = -1;
static int hf_middle                       = -1;
static int hf_data                         = -1;

static guint gPORT_PREF = 6789;

#define C_NEW_FILESCOPE(klass) ((klass*)wmem_alloc(wmem_file_scope(),   sizeof(klass)))
#define C_NEW_PKTSCOPE(klass)  ((klass*)wmem_alloc(wmem_packet_scope(), sizeof(klass)))

/* Initialize the subtree pointers */
static gint ett_ceph = -1;
static gint ett_sockaddr = -1;
static gint ett_connect = -1;
static gint ett_connect_reply = -1;

static const char *C_BANNER = "ceph";
enum c_banner {
	C_BANNER_LEN_MIN = 4,
	C_BANNER_LEN_MAX = 30,
};

enum c_inet {
	C_IPv4 = 0x02,
	C_IPv6 = 0x0A
};

static const value_string c_inet_strings[] = {
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

static const value_string c_tag_strings[] = {
	{C_TAG_READY,          "server->client: ready for messages"                 },
	{C_TAG_RESETSESSION,   "server->client: reset, try again"                   },
	{C_TAG_WAIT,           "server->client: wait for racing incoming connection"},
	{C_TAG_RETRY_SESSION,  "server->client + cseq: try again with higher cseq"  },
	{C_TAG_RETRY_GLOBAL,   "server->client + gseq: try again with higher gseq"  },
	{C_TAG_CLOSE,          "closing pipe"                                       },
	{C_TAG_MSG,            "message"                                            },
	{C_TAG_ACK,            "message ack"                                        },
	{C_TAG_KEEPALIVE,      "just a keepalive byte!"                             },
	{C_TAG_BADPROTOVER,    "bad protocol version"                               },
	{C_TAG_BADAUTHORIZER,  "bad authorizer"                                     },
	{C_TAG_FEATURES,       "insufficient features"                              },
	{C_TAG_SEQ,            "64-bit int follows with seen seq number"            },
	{C_TAG_KEEPALIVE2,     "Keepalive"                                          },
	{C_TAG_KEEPALIVE2_ACK, "keepalive reply"                                    },
};

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

static const value_string c_msg_type_strings[] = {
	{C_CEPH_MSG_SHUTDOWN,               "CEPH_MSG_SHUTDOWN"              },
	{C_CEPH_MSG_PING,                   "CEPH_MSG_PING"                  },
	{C_CEPH_MSG_MON_MAP,                "CEPH_MSG_MON_MAP"               },
	{C_CEPH_MSG_MON_GET_MAP,            "CEPH_MSG_MON_GET_MAP"           },
	{C_CEPH_MSG_STATFS,                 "CEPH_MSG_STATFS"                },
	{C_CEPH_MSG_STATFS_REPLY,           "CEPH_MSG_STATFS_REPLY"          },
	{C_CEPH_MSG_MON_SUBSCRIBE,          "CEPH_MSG_MON_SUBSCRIBE"         },
	{C_CEPH_MSG_MON_SUBSCRIBE_ACK,      "CEPH_MSG_MON_SUBSCRIBE_ACK"     },
	{C_CEPH_MSG_AUTH,                   "CEPH_MSG_AUTH"                  },
	{C_CEPH_MSG_AUTH_REPLY,             "CEPH_MSG_AUTH_REPLY"            },
	{C_CEPH_MSG_MON_GET_VERSION,        "CEPH_MSG_MON_GET_VERSION"       },
	{C_CEPH_MSG_MON_GET_VERSION_REPLY,  "CEPH_MSG_MON_GET_VERSION_REPLY" },
	{C_CEPH_MSG_MDS_MAP,                "CEPH_MSG_MDS_MAP"               },
	{C_CEPH_MSG_CLIENT_SESSION,         "CEPH_MSG_CLIENT_SESSION"        },
	{C_CEPH_MSG_CLIENT_RECONNECT,       "CEPH_MSG_CLIENT_RECONNECT"      },
	{C_CEPH_MSG_CLIENT_REQUEST,         "CEPH_MSG_CLIENT_REQUEST"        },
	{C_CEPH_MSG_CLIENT_REQUEST_FORWARD, "CEPH_MSG_CLIENT_REQUEST_FORWARD"},
	{C_CEPH_MSG_CLIENT_REPLY,           "CEPH_MSG_CLIENT_REPLY"          },
	{C_MSG_PAXOS,                       "MSG_PAXOS"                      },
	{C_CEPH_MSG_OSD_MAP,                "CEPH_MSG_OSD_MAP"               },
	{C_CEPH_MSG_OSD_OP,                 "CEPH_MSG_OSD_OP"                },
	{C_CEPH_MSG_OSD_OPREPLY,            "CEPH_MSG_OSD_OPREPLY"           },
	{C_CEPH_MSG_WATCH_NOTIFY,           "CEPH_MSG_WATCH_NOTIFY"          },
	{C_MSG_FORWARD,                     "MSG_FORWARD"                    },
	{C_MSG_ROUTE,                       "MSG_ROUTE"                      },
	{C_CEPH_MSG_POOLOP_REPLY,           "CEPH_MSG_POOLOP_REPLY"          },
	{C_MSG_POOLOPREPLY,                 "MSG_POOLOPREPLY"                },
	{C_CEPH_MSG_POOLOP,                 "CEPH_MSG_POOLOP"                },
	{C_MSG_POOLOP,                      "MSG_POOLOP"                     },
	{C_MSG_MON_COMMAND,                 "MSG_MON_COMMAND"                },
	{C_MSG_MON_COMMAND_ACK,             "MSG_MON_COMMAND_ACK"            },
	{C_MSG_LOG,                         "MSG_LOG"                        },
	{C_MSG_LOGACK,                      "MSG_LOGACK"                     },
	{C_MSG_MON_OBSERVE,                 "MSG_MON_OBSERVE"                },
	{C_MSG_MON_OBSERVE_NOTIFY,          "MSG_MON_OBSERVE_NOTIFY"         },
	{C_MSG_CLASS,                       "MSG_CLASS"                      },
	{C_MSG_CLASS_ACK,                   "MSG_CLASS_ACK"                  },
	{C_MSG_GETPOOLSTATS,                "MSG_GETPOOLSTATS"               },
	{C_MSG_GETPOOLSTATSREPLY,           "MSG_GETPOOLSTATSREPLY"          },
	{C_MSG_MON_GLOBAL_ID,               "MSG_MON_GLOBAL_ID"              },
	{C_CEPH_MSG_PRIO_LOW,               "CEPH_MSG_PRIO_LOW"              },
	{C_MSG_MON_SCRUB,                   "MSG_MON_SCRUB"                  },
	{C_MSG_MON_ELECTION,                "MSG_MON_ELECTION"               },
	{C_MSG_MON_PAXOS,                   "MSG_MON_PAXOS"                  },
	{C_MSG_MON_PROBE,                   "MSG_MON_PROBE"                  },
	{C_MSG_MON_JOIN,                    "MSG_MON_JOIN"                   },
	{C_MSG_MON_SYNC,                    "MSG_MON_SYNC"                   },
	{C_MSG_OSD_PING,                    "MSG_OSD_PING"                   },
	{C_MSG_OSD_BOOT,                    "MSG_OSD_BOOT"                   },
	{C_MSG_OSD_FAILURE,                 "MSG_OSD_FAILURE"                },
	{C_MSG_OSD_ALIVE,                   "MSG_OSD_ALIVE"                  },
	{C_MSG_OSD_MARK_ME_DOWN,            "MSG_OSD_MARK_ME_DOWN"           },
	{C_MSG_OSD_SUBOP,                   "MSG_OSD_SUBOP"                  },
	{C_MSG_OSD_SUBOPREPLY,              "MSG_OSD_SUBOPREPLY"             },
	{C_MSG_OSD_PGTEMP,                  "MSG_OSD_PGTEMP"                 },
	{C_MSG_OSD_PG_NOTIFY,               "MSG_OSD_PG_NOTIFY"              },
	{C_MSG_OSD_PG_QUERY,                "MSG_OSD_PG_QUERY"               },
	{C_MSG_OSD_PG_SUMMARY,              "MSG_OSD_PG_SUMMARY"             },
	{C_MSG_OSD_PG_LOG,                  "MSG_OSD_PG_LOG"                 },
	{C_MSG_OSD_PG_REMOVE,               "MSG_OSD_PG_REMOVE"              },
	{C_MSG_OSD_PG_INFO,                 "MSG_OSD_PG_INFO"                },
	{C_MSG_OSD_PG_TRIM,                 "MSG_OSD_PG_TRIM"                },
	{C_MSG_PGSTATS,                     "MSG_PGSTATS"                    },
	{C_MSG_PGSTATSACK,                  "MSG_PGSTATSACK"                 },
	{C_MSG_OSD_PG_CREATE,               "MSG_OSD_PG_CREATE"              },
	{C_MSG_REMOVE_SNAPS,                "MSG_REMOVE_SNAPS"               },
	{C_MSG_OSD_SCRUB,                   "MSG_OSD_SCRUB"                  },
	{C_MSG_OSD_PG_MISSING,              "MSG_OSD_PG_MISSING"             },
	{C_MSG_OSD_REP_SCRUB,               "MSG_OSD_REP_SCRUB"              },
	{C_MSG_OSD_PG_SCAN,                 "MSG_OSD_PG_SCAN"                },
	{C_MSG_OSD_PG_BACKFILL,             "MSG_OSD_PG_BACKFILL"            },
	{C_MSG_COMMAND,                     "MSG_COMMAND"                    },
	{C_MSG_COMMAND_REPLY,               "MSG_COMMAND_REPLY"              },
	{C_MSG_OSD_BACKFILL_RESERVE,        "MSG_OSD_BACKFILL_RESERVE"       },
	{C_MSG_MDS_BEACON,                  "MSG_MDS_BEACON"                 },
	{C_MSG_MDS_SLAVE_REQUEST,           "MSG_MDS_SLAVE_REQUEST"          },
	{C_MSG_MDS_TABLE_REQUEST,           "MSG_MDS_TABLE_REQUEST"          },
	{C_MSG_OSD_PG_PUSH,                 "MSG_OSD_PG_PUSH"                },
	{C_MSG_OSD_PG_PULL,                 "MSG_OSD_PG_PULL"                },
	{C_MSG_OSD_PG_PUSH_REPLY,           "MSG_OSD_PG_PUSH_REPLY"          },
	{C_MSG_OSD_EC_WRITE,                "MSG_OSD_EC_WRITE"               },
	{C_MSG_OSD_EC_WRITE_REPLY,          "MSG_OSD_EC_WRITE_REPLY"         },
	{C_MSG_OSD_EC_READ,                 "MSG_OSD_EC_READ"                },
	{C_MSG_OSD_EC_READ_REPLY,           "MSG_OSD_EC_READ_REPLY"          },
	{C_CEPH_MSG_PRIO_DEFAULT,           "CEPH_MSG_PRIO_DEFAULT"          },
	{C_MSG_OSD_RECOVERY_RESERVE,        "MSG_OSD_RECOVERY_RESERVE"       },
	{C_CEPH_MSG_PRIO_HIGH,              "CEPH_MSG_PRIO_HIGH"             },
	{C_CEPH_MSG_PRIO_HIGHEST,           "CEPH_MSG_PRIO_HIGHEST"          },
	{C_MSG_MDS_RESOLVE,                 "MSG_MDS_RESOLVE"                },
	{C_MSG_MDS_RESOLVEACK,              "MSG_MDS_RESOLVEACK"             },
	{C_MSG_MDS_CACHEREJOIN,             "MSG_MDS_CACHEREJOIN"            },
	{C_MSG_MDS_DISCOVER,                "MSG_MDS_DISCOVER"               },
	{C_MSG_MDS_DISCOVERREPLY,           "MSG_MDS_DISCOVERREPLY"          },
	{C_MSG_MDS_INODEUPDATE,             "MSG_MDS_INODEUPDATE"            },
	{C_MSG_MDS_DIRUPDATE,               "MSG_MDS_DIRUPDATE"              },
	{C_MSG_MDS_CACHEEXPIRE,             "MSG_MDS_CACHEEXPIRE"            },
	{C_MSG_MDS_DENTRYUNLINK,            "MSG_MDS_DENTRYUNLINK"           },
	{C_MSG_MDS_FRAGMENTNOTIFY,          "MSG_MDS_FRAGMENTNOTIFY"         },
	{C_MSG_MDS_OFFLOAD_TARGETS,         "MSG_MDS_OFFLOAD_TARGETS"        },
	{C_MSG_MDS_DENTRYLINK,              "MSG_MDS_DENTRYLINK"             },
	{C_MSG_MDS_FINDINO,                 "MSG_MDS_FINDINO"                },
	{C_MSG_MDS_FINDINOREPLY,            "MSG_MDS_FINDINOREPLY"           },
	{C_MSG_MDS_OPENINO,                 "MSG_MDS_OPENINO"                },
	{C_MSG_MDS_OPENINOREPLY,            "MSG_MDS_OPENINOREPLY"           },
	{C_MSG_MDS_LOCK,                    "MSG_MDS_LOCK"                   },
	{C_MSG_MDS_INODEFILECAPS,           "MSG_MDS_INODEFILECAPS"          },
	{C_CEPH_MSG_CLIENT_CAPS,            "CEPH_MSG_CLIENT_CAPS"           },
	{C_CEPH_MSG_CLIENT_LEASE,           "CEPH_MSG_CLIENT_LEASE"          },
	{C_CEPH_MSG_CLIENT_SNAP,            "CEPH_MSG_CLIENT_SNAP"           },
	{C_CEPH_MSG_CLIENT_CAPRELEASE,      "CEPH_MSG_CLIENT_CAPRELEASE"     },
	{C_MSG_MDS_EXPORTDIRDISCOVER,       "MSG_MDS_EXPORTDIRDISCOVER"      },
	{C_MSG_MDS_EXPORTDIRDISCOVERACK,    "MSG_MDS_EXPORTDIRDISCOVERACK"   },
	{C_MSG_MDS_EXPORTDIRCANCEL,         "MSG_MDS_EXPORTDIRCANCEL"        },
	{C_MSG_MDS_EXPORTDIRPREP,           "MSG_MDS_EXPORTDIRPREP"          },
	{C_MSG_MDS_EXPORTDIRPREPACK,        "MSG_MDS_EXPORTDIRPREPACK"       },
	{C_MSG_MDS_EXPORTDIRWARNING,        "MSG_MDS_EXPORTDIRWARNING"       },
	{C_MSG_MDS_EXPORTDIRWARNINGACK,     "MSG_MDS_EXPORTDIRWARNINGACK"    },
	{C_MSG_MDS_EXPORTDIR,               "MSG_MDS_EXPORTDIR"              },
	{C_MSG_MDS_EXPORTDIRACK,            "MSG_MDS_EXPORTDIRACK"           },
	{C_MSG_MDS_EXPORTDIRNOTIFY,         "MSG_MDS_EXPORTDIRNOTIFY"        },
	{C_MSG_MDS_EXPORTDIRNOTIFYACK,      "MSG_MDS_EXPORTDIRNOTIFYACK"     },
	{C_MSG_MDS_EXPORTDIRFINISH,         "MSG_MDS_EXPORTDIRFINISH"        },
	{C_MSG_MDS_EXPORTCAPS,              "MSG_MDS_EXPORTCAPS"             },
	{C_MSG_MDS_EXPORTCAPSACK,           "MSG_MDS_EXPORTCAPSACK"          },
	{C_MSG_MDS_HEARTBEAT,               "MSG_MDS_HEARTBEAT"              },
	{C_MSG_TIMECHECK,                   "MSG_TIMECHECK"                  },
	{C_MSG_MON_HEALTH,                  "MSG_MON_HEALTH"                 },
};

typedef enum _c_node_type {
	C_NODE_TYPE_UNKNOWN = 0x00,
	C_NODE_TYPE_MON     = 0x01,
	C_NODE_TYPE_MDS     = 0x02,
	C_NODE_TYPE_OSD     = 0x04,
	C_NODE_TYPE_CLIENT  = 0x08,
	C_NODE_TYPE_AUTH    = 0x20
} c_node_type;

static const value_string c_node_type_strings[] = {
	{C_NODE_TYPE_UNKNOWN, "Unknown"              },
	{C_NODE_TYPE_MON,     "Monitor"              },
	{C_NODE_TYPE_MDS,     "Meta Data Server"     },
	{C_NODE_TYPE_OSD,     "Object Storage Daemon"},
	{C_NODE_TYPE_CLIENT,  "Client"               },
	{C_NODE_TYPE_AUTH,    "Authentication Server"}
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
	//n->addr;
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

typedef struct _c_pkt_data {
	conversation_t *conv; /* The wireshark conversation. */
	c_conv_data *convd;   /* The Ceph conversation data. */
	c_node *src;          /* The node in convd that sent this message. */
	c_node *dst;          /* The node in convd that is receiving this message. */
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
	gboolean visited;
	
	/* Get conversation to store/retrieve connection data. */
	d->conv = find_or_create_conversation(pinfo);
	g_assert(d->conv);
	
	/* If we have dissected this packet before get saved state. */
	d->convd = (c_conv_data*)p_get_proto_data(wmem_file_scope(), pinfo, proto_ceph, offset);
	visited = !!d->convd;
	
	if (d->convd)
	{
		/*
			We have dissected this packet before, copy the saved state so
			that we don't mess up the saved state.
		*/
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
	
	if (!visited)
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

/***** Protocol Dissector *****/

/*** A couple of magic marcos ***/
/*
 * These macros are very magic and expect the proper variable names to exist
 * in the scope.
 */

/* Specify the size of the packet.
 * 
 * This macro should be called once you know how much data is in the PDU.  The
 * amount is calculated relative to the current offset (in off).  This function
 * must only be called once the exact size of the PDU is known.  If more data
 * is needed to determine the size of the PDU C_HEADER_SIZE() can be used.
 * 
 * This macro ensures that there is enough data remaining in the buffer and if
 * not it returns, requesting the exact amount of data required.
 */
#define C_PACKET_SIZE(n) do{          \
		if (!tvb_bytes_exist(tvb, off, n)) \
			return off+(n);                \
	}while(0)

/* Specify the amount of data required to determine the packet length.
 * 
 * This function is similar to C_PACKET_SIZE() except that it does not
 * request the exact amount of data required but instead just asks for another
 * "chunk".
 */
#define C_HEADER_SIZE(n) do{          \
		if (!tvb_bytes_exist(tvb, off, n)) \
			return 0;                      \
	}while(0)

/* Add an item to the proto tree.
 * 
 * Adds an item hf found at offset o of size l to the proto tree.  This
 * assumes little endian encoding.
 */
#define  ADD(hf, o, l) proto_tree_add_item(tree   , hf, tvb, o, l, ENC_LITTLE_ENDIAN)

/* Add an item to a subtree.
 * 
 * Like ADD() but instead of using the tree named `tree` use `subtree`.
 */
#define ADDS(hf, o, l) proto_tree_add_item(subtree, hf, tvb, o, l, ENC_LITTLE_ENDIAN)

/* Add an item to the proto tree and advance the offset.
 * 
 * This function is like ADD() except that it uses the current offset and
 * advances the offset by `l` afterwards.
 */
#define  EAT(hf, l) do{ ADD (hf, off, l); off += l; }while(0)

/* Add an item to a subtree and advance the offset.
 * 
 * The same as EAT() except for a subtree.
 * 
 * This function is to EAT() what ADDS() is to ADD();
 */
#define EATS(hf, l) do{ ADDS(hf, off, l); off += l; }while(0)

/*** Dissector Functions ***/

enum c_size_sockaddr {
	C_SIZE_SOCKADDR_STORAGE = 128
};

static
guint c_dissect_sockaddr(proto_tree *root, int hf,
                         tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	guint16 af;
	proto_item *ti;
	proto_tree *tree;
	
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
	
	ti = proto_tree_add_item(root, hf, tvb, off, C_SIZE_SOCKADDR_STORAGE, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_sockaddr);
	
	af = tvb_get_ntohs(tvb, off);
	
	proto_tree_add_item(tree, hf_inet_family, tvb, off, 2, ENC_BIG_ENDIAN);
	
	switch (af) {
	case C_IPv4:
		proto_tree_add_item(tree, hf_port, tvb, off+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_addr_ipv4, tvb, off+4, 4, ENC_BIG_ENDIAN);
		break;
	case C_IPv6: //@UNTESTED
		proto_tree_add_item(tree, hf_port, tvb, off+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_addr_ipv6, tvb, off+8, 16, ENC_BIG_ENDIAN);
		break;
	default:
		printf("UNKNOWN INET %x!\n", af);
	}
	off += C_SIZE_SOCKADDR_STORAGE; // Skip over sockaddr_storage.
	
	return off;
}

static
guint c_dissect_features(proto_tree *root,
                      tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, hf_features,
	                         tvb, off, 8, ENC_LITTLE_ENDIAN);
	tree = proto_item_add_subtree(ti, hf_features);
	
	/* Wireshark doesn't have support for 64 bit bitfields so dissect as
	   two 32 bit ones. */
	ADD(hf_feature_uid,                  off, 4);
	ADD(hf_feature_nosrcaddr,            off, 4);
	ADD(hf_feature_monclockcheck,        off, 4);
	ADD(hf_feature_flock,                off, 4);
	ADD(hf_feature_subscribe2,           off, 4);
	ADD(hf_feature_monnames,             off, 4);
	ADD(hf_feature_reconnect_seq,        off, 4);
	ADD(hf_feature_dirlayouthash,        off, 4);
	ADD(hf_feature_objectlocator,        off, 4);
	ADD(hf_feature_pgid64,               off, 4);
	ADD(hf_feature_incsubosdmap,         off, 4);
	ADD(hf_feature_pgpool3,              off, 4);
	ADD(hf_feature_osdreplymux,          off, 4);
	ADD(hf_feature_osdenc,               off, 4);
	ADD(hf_feature_omap,                 off, 4);
	ADD(hf_feature_monenc,               off, 4);
	ADD(hf_feature_query_t,              off, 4);
	ADD(hf_feature_indep_pg_map,         off, 4);
	ADD(hf_feature_crush_tunables,       off, 4);
	ADD(hf_feature_chunky_scrub,         off, 4);
	ADD(hf_feature_mon_nullroute,        off, 4);
	ADD(hf_feature_mon_gv,               off, 4);
	ADD(hf_feature_backfill_reservation, off, 4);
	ADD(hf_feature_msg_auth,             off, 4);
	ADD(hf_feature_recovery_reservation, off, 4);
	ADD(hf_feature_crush_tunables2,      off, 4);
	ADD(hf_feature_createpoolid,         off, 4);
	ADD(hf_feature_reply_create_inode,   off, 4);
	ADD(hf_feature_osd_hbmsgs,           off, 4);
	ADD(hf_feature_mdsenc,               off, 4);
	ADD(hf_feature_osdhashpspool,        off, 4);
	ADD(hf_feature_mon_single_paxos,     off, 4);
	
	off += 4; /* Next 32 bits. */
	
	ADD(hf_feature_osd_snapmapper,       off, 4);
	ADD(hf_feature_mon_scrub,            off, 4);
	ADD(hf_feature_osd_packed_recovery,  off, 4);
	ADD(hf_feature_osd_cachepool,        off, 4);
	ADD(hf_feature_crush_v2,             off, 4);
	ADD(hf_feature_export_peer,          off, 4);
	ADD(hf_feature_osd_erasure_codes,    off, 4);
	ADD(hf_feature_osd_tmap2omap,        off, 4);
	ADD(hf_feature_osdmap_enc,           off, 4);
	ADD(hf_feature_mds_inline_data,      off, 4);
	ADD(hf_feature_crush_tunables3,      off, 4);
	ADD(hf_feature_osd_primary_affinity, off, 4);
	ADD(hf_feature_msgr_keepalive2,      off, 4);
	ADD(hf_feature_reserved,             off, 4);
	
	off += 4;
	
	return off;
}

static
guint c_dissect_flags(proto_tree *root,
                    tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, hf_flags,
	                         tvb, off, 1, ENC_LITTLE_ENDIAN);
	tree = proto_item_add_subtree(ti, hf_flags);
	
	ADD(hf_flag_lossy, off, 1); off += 1;
	
	return off;
}

enum c_sizes_connect {
	C_SIZE_CONNECT = 33,
	C_SIZE_CONNECT_REPLY = 25,
	C_SIZE_HELLO_S = 2*(8+C_SIZE_SOCKADDR_STORAGE),
	C_SIZE_HELLO_C = 8 + C_SIZE_SOCKADDR_STORAGE + C_SIZE_CONNECT
};

static
guint c_dissect_connect(proto_tree *root,
                        tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
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
	tree = proto_item_add_subtree(ti, ett_connect);
	
	off = c_dissect_features(tree, tvb, off, data);
	
	EAT(hf_connect_host_type,  4);
	EAT(hf_connect_seq_global, 4);
	EAT(hf_connect_seq,        4);
	EAT(hf_connect_proto_ver,  4);
	EAT(hf_connect_auth_proto, 4);
	EAT(hf_connect_auth_len,   4);
	
	off = c_dissect_flags(tree, tvb, off, data);
	
	return off;
}

static
guint c_dissect_connect_reply(proto_tree *root,
                              tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
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
	
	C_PACKET_SIZE(C_SIZE_CONNECT_REPLY);
	
	ti = proto_tree_add_item(root, hf_connect_reply, tvb,
	                         off, C_SIZE_CONNECT_REPLY,
	                         ENC_NA);
	tree = proto_item_add_subtree(ti, ett_connect_reply);
	
	off = c_dissect_features(tree, tvb, off, data);
	
	EAT(hf_connect_seq_global, 4);
	EAT(hf_connect_seq,        4);
	EAT(hf_connect_proto_ver,  4);
	EAT(hf_connect_auth_len,   4);
	
	off = c_dissect_flags(tree, tvb, off, data);
	
	return off;
}

enum c_size_entity_name {
	C_SIZE_ENTITY_NAME = 9
};

static
guint c_dissect_entity_name(proto_tree *root, packet_info *pinfo _U_,
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
	
	EAT(hf_node_type, 1);
	EAT(hf_node_id,   8);
	
	return off;
}

/** Do the connection initiation dance.
 * 
 * This handles the data is sent before the protocol is actually started.
 */
static
guint c_dissect_new(proto_tree *tree, packet_info *pinfo,
                  tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	gint banlen;
	
	/*
		Since the packet is larger than the max banner length we can read it
		all in safely.
	*/
	G_STATIC_ASSERT(C_BANNER_LEN_MAX+1 <= C_BANNER_LEN_MIN+C_SIZE_HELLO_C);
	G_STATIC_ASSERT(C_BANNER_LEN_MAX+1 <= C_BANNER_LEN_MIN+C_SIZE_HELLO_S);
	
	C_HEADER_SIZE(C_BANNER_LEN_MAX+1);
	
	if (tvb_memeql(tvb, off, C_BANNER, C_BANNER_LEN_MIN) != 0)
		return 0; // Invalid banner.
	
	banlen = tvb_strnlen(tvb, off, C_BANNER_LEN_MAX+1);
	if (banlen == -1)
		return 0; // Invalid banner.
	
	proto_tree_add_item(tree, hf_version, tvb, off, banlen, ENC_NA);
	off += banlen;
	
	C_PACKET_SIZE(c_from_server(data)? C_SIZE_HELLO_S : C_SIZE_HELLO_C);
	
	col_set_str(pinfo->cinfo, COL_INFO, "Hello");
	
	if (c_from_server(data))
	{
		//@TODO: Why is there an 8-byte offset?
		off += 8;
		
		off = c_dissect_sockaddr(tree, hf_sockaddr_server, tvb, off, data);
	}
	
	//@TODO: Why this offset?
	off += 8;
	
	off = c_dissect_sockaddr(tree, hf_sockaddr_client, tvb, off, data);
	
	if (c_from_client(data))
	{
		off = c_dissect_connect(tree, tvb, off, data);
	}
	
	data->src->state = C_STATE_OPEN;
	
	return off;
}

enum c_size_msg{
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
guint c_dissect_msg(proto_tree *tree, packet_info *pinfo,
                  tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *subtree;
	guint32 front_len, middle_len, data_len;
	
	C_HEADER_SIZE(C_OFF_HEAD1 + C_SIZE_HEAD1);
	
	front_len  = tvb_get_letoh64(tvb, off + C_OFF_HEAD1 + 0);
	middle_len = tvb_get_letoh64(tvb, off + C_OFF_HEAD1 + 4);
	data_len   = tvb_get_letoh64(tvb, off + C_OFF_HEAD1 + 8);
	
	C_PACKET_SIZE(C_SIZE_HEAD+front_len+middle_len+data_len+C_SIZE_FOOT);
	
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
	
	EATS(hf_head_seq,      8);
	EATS(hf_head_tid,      8);
	EATS(hf_head_type,     2);
	EATS(hf_head_priority, 2);
	EATS(hf_head_version,  2);
	
	EATS(hf_head_front_len,  4);
	EATS(hf_head_middle_len, 4);
	EATS(hf_head_data_len,   4);
	EATS(hf_head_data_off,   2);
	
	off = c_dissect_entity_name(subtree, pinfo, tvb, off, data);
	
	EATS(hf_head_compat_version, 2);
	EATS(hf_head_reserved,       2);
	EATS(hf_head_crc,            4);
	
	/*** Body ***/
	
	EAT(hf_front, front_len);
	EAT(hf_middle, middle_len);
	EAT(hf_data, data_len);
	
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
	
	EATS(hf_foot_front_crc,  4);
	EATS(hf_foot_middle_crc, 4);
	EATS(hf_foot_data_crc,   4);
	
	EATS(hf_foot_signature,  8);
	off = c_dissect_flags(subtree, tvb, off, data); /* @HELP: Can we do this? */
	
	return off;
}

/* Dissect a MSGR message.
 * 
 * MSGR is Ceph's outer message protocol.
 */
static
guint c_dissect_msgr(proto_tree *tree, packet_info *pinfo,
                   tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	guint8 tag;
	
	C_HEADER_SIZE(1);
	
	tag = tvb_get_guint8(tvb, off);
	ADD(hf_tag, off, 1);
	off += 1;
	
	switch (tag)
	{
	case C_TAG_READY:
		off = c_dissect_connect_reply(tree, tvb, off, data);
		break;
	case C_TAG_RESETSESSION:
		//@TODO
		break;
	case C_TAG_WAIT:
		//@TODO
		break;
	case C_TAG_RETRY_SESSION:
		//@TODO
		break;
	case C_TAG_RETRY_GLOBAL:
		//@TODO
		break;
	case C_TAG_CLOSE:
		//@TODO
		break;
	case C_TAG_MSG:
		off = c_dissect_msg(tree, pinfo, tvb, off, data);
		break;
	case C_TAG_ACK:
		C_PACKET_SIZE(8);
		EAT(hf_ack, 8);
		break;
	case C_TAG_KEEPALIVE:
		/* No data. */
		break;
	case C_TAG_BADPROTOVER:
		//@TODO
		break;
	case C_TAG_BADAUTHORIZER:
		//@TODO
		break;
	case C_TAG_FEATURES:
		//@TODO
		break;
	case C_TAG_SEQ:
		//@TODO
		break;
	case C_TAG_KEEPALIVE2:
		//@TODO
		break;
	case C_TAG_KEEPALIVE2_ACK:
		//@TODO
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
		;
	}
	
	return off;
}

/* Dissect a Protocol Data Unit
 */
static
guint c_dissect_pdu(proto_tree *root, packet_info *pinfo,
                  tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	
	col_set_str(pinfo->cinfo, COL_INFO, "Malformed");
	ti = proto_tree_add_item(root, proto_ceph, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_ceph);
	
	if (data->src->state == C_STATE_NEW)
		off = c_dissect_new(tree, pinfo, tvb, off, data);
	else
		off = c_dissect_msgr(tree, pinfo, tvb, off, data);
	
	proto_item_set_len(ti, off);
	return off;
}

static int
dissect_ceph(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *pdata _U_)
{
	guint off, offt;
	c_pkt_data data;
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ceph");
	col_clear(pinfo->cinfo, COL_INFO);
	
	off = 0;
	while (off < tvb_reported_length(tvb))
	{
		c_pkt_data_init(&data, pinfo, off);
		
		offt = c_dissect_pdu(tree, pinfo, tvb, off, &data);
		if (offt == 0)
		{
			pinfo->desegment_offset = off;
			pinfo->desegment_len    = DESEGMENT_ONE_MORE_SEGMENT;
			return 1;
		}
		if (offt > tvb_reported_length(tvb))
		{
			pinfo->desegment_offset = off;
			pinfo->desegment_len    = offt - off - tvb_reported_length(tvb);
			return 1;
		}
		
		off = offt;
	}
	
	return off; // Perfect Fit.
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_ceph(void)
{
	module_t *ceph_module;
	//expert_module_t* expert_ceph;
	
	static hf_register_info hf[] = {
		{ &hf_type, {
			"Type", "ceph.type",
			FT_UINT8, BASE_HEX, NULL, 0,
			"The message type.", HFILL
		} },
		{ &hf_node_id, {
			"ID", "ceph.node_id",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The numeric ID of the node.", HFILL
		} },
		{ &hf_node_type, {
			"Source Node Type", "ceph.node_type",
			FT_UINT8, BASE_HEX, VALS(&c_node_type_strings), 0,
			"The type of source node.", HFILL
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
		{ &hf_sockaddr_server, {
			"Server's Network Address", "ceph.server.sockaddr",
			FT_NONE, BASE_NONE, NULL, 0,
			"The address of the server according to itself.", HFILL
		} },
		{ &hf_sockaddr_client, {
			"Client's Network Address", "ceph.client.sockaddr",
			FT_NONE, BASE_NONE, NULL, 0,
			"The address of the client as seen by the server.", HFILL
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
			FT_UINT32, BASE_HEX, VALS(&c_node_type_strings), 0,
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
			FT_UINT8, BASE_HEX, VALS(&c_tag_strings), 0,
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
			FT_UINT16, BASE_HEX, VALS(&c_msg_type_strings), 0,
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
		{ &hf_front, {
			"Front", "ceph.front",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_middle, {
			"Middle", "ceph.mid",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_data, {
			"Data", "ceph.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
	};
	
	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ceph,
		&ett_sockaddr,
		&ett_connect,
		&ett_connect_reply,
	};
	
	/* Register the protocol name and description */
	proto_ceph = proto_register_protocol("Ceph", "Ceph", "ceph");
	
	/* Required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_ceph, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	
	/*** Preferences ***/
	ceph_module = prefs_register_protocol(proto_ceph, proto_reg_handoff_ceph);
	
	prefs_register_uint_preference(ceph_module,
		"tcp.port", "Ceph TCP Port",
		" Ceph TCP port if other than the default",
		10, &gPORT_PREF
	);
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
	static gboolean initialized = FALSE;
	static dissector_handle_t ceph_handle;
	static int currentPort;
	
	if (!initialized) {
		/* Use new_create_dissector_handle() to indicate that
		 * dissect_ceph() returns the number of bytes it dissected (or 0
		 * if it thinks the packet does not belong to PROTONAME).
		 */
		ceph_handle = new_create_dissector_handle(dissect_ceph, proto_ceph);
		initialized = TRUE;
	
	} else {
		/* If you perform registration functions which are dependent upon
		 * prefs then you should de-register everything which was associated
		 * with the previous settings and re-register using the new prefs
		 * settings here. In general this means you need to keep track of
		 * the ceph_handle and the value the preference had at the time
		 * you registered.	The ceph_handle value and the value of the
		 * preference can be saved using local statics in this
		 * function (proto_reg_handoff).
		 */
		dissector_delete_uint("tcp.port", currentPort, ceph_handle);
	}
	
	currentPort = gPORT_PREF;
	dissector_add_uint("tcp.port", currentPort, ceph_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 noexpandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
